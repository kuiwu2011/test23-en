async function hashPassword(password, salt) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${salt}:${password}`));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmac(message, secret) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getSessionUser(request, env) {
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  if (!m) return null;
  const decoded = decodeURIComponent(m[1]);
  const idx = decoded.lastIndexOf('|sig=');
  if (idx < 0) return null;
  const raw = decoded.slice(0, idx);
  const expect = decoded.slice(idx + 5);
  const actual = await hmac(raw, env.SESSION_SECRET || 'change_me');
  if (actual !== expect) return null;
  const userMatch = raw.match(/^user=(.*)$/);
  return userMatch ? userMatch[1] : null;
}

async function ensureTables(db) {
  await db.prepare(
    "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)"
  ).run();
  await db.prepare(
    "CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, content TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')))"
  ).run();
}

function setSession(headers, username, env) {
  const SECRET = env.SESSION_SECRET || 'change_me';
  const raw = `user=${username}`;
  return hmac(raw, SECRET).then(sig => {
    const cookie = `${raw}|sig=${sig}`;
    headers.append('Set-Cookie', `session=${encodeURIComponent(cookie)}; Path=/; HttpOnly; SameSite=Lax`);
    headers.append('Set-Cookie', `username=${encodeURIComponent(username)}; Path=/; Max-Age=86400; SameSite=Lax`);
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      await ensureTables(env.DB);
    } catch (e) {
      // 表初始化失败不阻断，交给具体 handler 报错
    }

    // POST /login
    if (path === '/login' && method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return json({ success: false, message: '请求格式错误' }, 400); }

      const { user, pass } = body;
      const SALT = env.PASSWORD_SALT || 'default_salt_please_change';

      // 固定管理员登录
      if (env.ADMIN_USER && env.ADMIN_PASS && user === env.ADMIN_USER && pass === env.ADMIN_PASS) {
        const headers = new Headers();
        await setSession(headers, user, env);
        headers.set('Content-Type', 'application/json');
        return new Response(JSON.stringify({ success: true, message: '登录成功' }), { headers });
      }

      // D1 用户登录
      try {
        const hash = await hashPassword(pass, SALT);
        const { results } = await env.DB.prepare(
          "SELECT id FROM users WHERE username = ? AND password_hash = ?"
        ).bind(user, hash).all();

        if (results.length > 0) {
          const headers = new Headers();
          await setSession(headers, user, env);
          headers.set('Content-Type', 'application/json');
          return new Response(JSON.stringify({ success: true }), { headers });
        }
      } catch (e) {}

      return json({ success: false, message: '账号或密码错误' }, 401);
    }

    // /logout
    if (path === '/logout') {
      return new Response(null, {
        status: 302,
        headers: {
          'Location': '/',
          'Set-Cookie': 'session=; Path=/; Max-Age=0, username=; Path=/; Max-Age=0'
        }
      });
    }

    // GET /messages
    if (path === '/messages' && method === 'GET') {
      const username = await getSessionUser(request, env);
      let results = [];
      try {
        results = (await env.DB.prepare(
          "SELECT name, content FROM messages ORDER BY id DESC LIMIT 50"
        ).all()).results;
      } catch (e) {}

      return json({ loggedIn: !!username, username: username || '', messages: results });
    }

    // POST /messages
    if (path === '/messages' && method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return json({ success: false, message: '请求格式错误' }, 400); }

      const username = await getSessionUser(request, env);
      const action = body.action;
      const SALT = env.PASSWORD_SALT || 'default_salt_please_change';

      // 注册
      if (action === 'register') {
        const { username: regUser, password } = body;
        if (!regUser || !password) return json({ success: false, message: '缺少字段' }, 400);

        const hash = await hashPassword(password, SALT);
        try {
          await env.DB.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
            .bind(regUser, hash).run();
        } catch (e) {
          return json({ success: false, message: '账号已存在' }, 409);
        }
        return json({ success: true, message: '注册成功' }, 201);
      }

      // 登录
      if (action === 'login') {
        const { username: loginUser, password } = body;
        const hash = await hashPassword(password, SALT);
        const { results } = await env.DB.prepare(
          "SELECT id FROM users WHERE username = ? AND password_hash = ?"
        ).bind(loginUser, hash).all();

        if (results.length === 0) return json({ success: false, message: '账号或密码错误' }, 401);

        const headers = new Headers();
        await setSession(headers, loginUser, env);
        headers.set('Content-Type', 'application/json');
        return new Response(JSON.stringify({ success: true }), { headers });
      }

      // 发留言
      if (action === 'message') {
        if (!username) return json({ success: false, message: '未登录' }, 401);
        const { content } = body;
        if (!content || !content.trim()) return json({ success: false, message: '内容为空' }, 400);

        await env.DB.prepare("INSERT INTO messages (name, content) VALUES (?, ?)")
          .bind(username, content).run();
        return json({ success: true }, 201);
      }

      return json({ success: false, message: '无效操作' }, 400);
    }

    // 其余请求交给静态资源（HTML/JS/CSS）
    return env.ASSETS.fetch(request);
  }
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}