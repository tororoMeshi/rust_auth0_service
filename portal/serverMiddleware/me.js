// serverMiddleware/me.js
export default function (req, res, next) {
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) {
    res.statusCode = 401;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'Not authenticated' }));
    return;
  }
  const cookies = {};
  cookieHeader.split(';').forEach(cookie => {
    const parts = cookie.split('=');
    cookies[parts[0].trim()] = (parts[1] || '').trim();
  });
  
  // ここでは session_id が存在すれば認証済みと判断
  if (cookies.session_id) {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({
      user: {
        id: 1,
        email: 'user@example.com',
        name: 'Demo User'
      }
    }));
  } else {
    res.statusCode = 401;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'Not authenticated' }));
  }
}
