<template>
    <div class="login-error">
      <h1>Login Error Occurred</h1>
      <p style="color: red;">{{ errorMessage }}</p>
      <p>Please try logging in again.</p>
      <button @click="retryLogin">Retry Login</button>
    </div>
  </template>
  
  <script>
  export default {
    computed: {
      // クエリパラメータから error を取得。なければデフォルトのメッセージを表示。
      errorMessage() {
        return this.$route.query.error || "An unknown error occurred.";
      }
    },
    methods: {
      retryLogin() {
        // 再ログインのため、認証サーバーへリダイレクトする。
        // ここでは、リダイレクト先を dashboard に設定していますが、必要に応じて調整してください。
        window.location.href = "https://auth.tororomeshi.net/auth/google?redirect=" + encodeURIComponent("https://app.tororomeshi.net/dashboard");
      }
    }
  }
  </script>
  
  <style scoped>
  .login-error {
    max-width: 600px;
    margin: 0 auto;
    padding: 2em;
    text-align: center;
  }
  button {
    margin-top: 1em;
    padding: 0.8em 1.5em;
    font-size: 1em;
    cursor: pointer;
  }
  </style>
  