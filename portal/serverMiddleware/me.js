// serverMiddleware/me.js

const jwt = require('jsonwebtoken');
const cookie = require('cookie');

// JWT_SECRET を環境変数から取得。必ず本番環境では安全に管理してください。
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("JWT_SECRET environment variable is not set.");
  // 本番環境では、起動前に必ず設定すること
}

module.exports = function (req, res, next) {
  // アクセスログを出力
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} - IP: ${req.connection.remoteAddress}`);
  
  // cookie パッケージを使用して、リクエストヘッダーからクッキーをパース
  const cookies = cookie.parse(req.headers.cookie || '');

  if (!cookies.jwt) {
    res.statusCode = 401;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'Not authenticated: JWT missing' }));
    return;
  }

  try {
    // JWT の署名検証を実施
    const decoded = jwt.verify(cookies.jwt, JWT_SECRET);
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ user: decoded }));
  } catch (err) {
    console.error("JWT verification failed:", err);
    res.statusCode = 401;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'Invalid JWT', details: err.message }));
  }
};
