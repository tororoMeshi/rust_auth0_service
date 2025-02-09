export default {
    // SSR モードを有効に（本番環境向け）
    ssr: true,
    target: 'server',
    // グローバルミドルウェア、プラグインの設定（認証、CSRF などを後で追加）
    modules: [
      '@nuxtjs/axios'
    ],
    axios: {
      // API のベースURLは環境に合わせる（例：内部ネットワーク経由の場合）
      baseURL: process.env.API_BASE_URL || 'https://auth.tororomeshi.net'
    },
    serverMiddleware: [
      // 認証状態確認用のシンプルなエンドポイント例（本番では uniauth との連携やセッション検証を行う）
      { path: '/api/me', handler: '~/serverMiddleware/me.js' }
    ]
  }
  