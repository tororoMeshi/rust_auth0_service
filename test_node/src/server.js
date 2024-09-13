const express = require('express');

const app = express();

app.use(express.static('public'));

app.get('/auth/callback', async (req, res) => {
    const code = req.query.code;

    // 標準の fetch API を使用
    const response = await fetch(`http://localhost:8080/auth/google/callback?code=${code}`);
    const userInfo = await response.json();

    const redirectUrl = `/index.html?email=${encodeURIComponent(userInfo.email)}&picture=${encodeURIComponent(userInfo.picture)}`;
    res.redirect(redirectUrl);
});

app.listen(3000, () => {
    console.log('Test application is running on http://localhost:3000');
});

