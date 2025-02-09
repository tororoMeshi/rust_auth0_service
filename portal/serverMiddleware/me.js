// ※本番では uniauth のセッション検証 API をコールすることが望ましい
export default function (req, res, next) {
    const cookieHeader = req.headers.cookie;
    if (!cookieHeader) {
      res.statusCode = 401;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Not authenticated' }));
      return;
    }
    // シンプルな Cookie パース（本番では robust なライブラリ使用推奨）
    const cookies = {};
    cookieHeader.split(';').forEach(cookie => {
      let parts = cookie.split('=');
      cookies[parts[0].trim()] = (parts[1] || '').trim();
    });
    
    if (cookies.session_id) {
      // ここで uniauth の /upsert_and_token で発行されたセッションID の検証を行う
      // サンプルとして固定のユーザー情報を返却
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
  