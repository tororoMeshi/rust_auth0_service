export default {
  // SSR（サーバーサイドレンダリング）を有効にしたユニバーサルモード
  ssr: true,
  target: 'server',
  
  // Global page headers
  head: {
    title: 'Portal Site',
    meta: [
      { charset: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { hid: 'description', name: 'description', content: 'User portal for login and dashboard' }
    ]
  },

  // Modules
  modules: [
    '@nuxtjs/axios'
  ],
  
  axios: {
    // 相対パスに設定することで、自身のオリジン（app.tororomeshi.net）にリクエストが送られる
    baseURL: process.env.API_BASE_URL || '/'
  },

  // サーバーミドルウェア
  serverMiddleware: [
    { path: '/api/me', handler: '~/serverMiddleware/me.js' }
  ]
}
