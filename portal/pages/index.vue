<template>
  <div class="login-page">
    <h1>Welcome to the Portal</h1>
    <!-- Google ログインボタン -->
    <button @click="login">Login with Google</button>
    <!-- ダッシュボードへのアクセスボタン -->
    <button @click="goToDashboard">Go to Dashboard</button>
  </div>
</template>

<script>
export default {
  methods: {
    login() {
      // 現在の完全な URL を取得（例: https://app.tororomeshi.net/dashboard など）
      const currentUrl = window.location.href;
      // 認証サーバー (auth.tororomeshi.net) に対して、リダイレクト先として完全な URL をクエリパラメータに設定
      window.location.href = "https://auth.tororomeshi.net/auth/google?redirect=" + encodeURIComponent(currentUrl);
    },
    goToDashboard() {
      // ダッシュボードへ移動
      this.$router.push('/dashboard');
    }
  }
}
</script>

<style scoped>
.login-page {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
}
button {
  margin: 10px;
  padding: 1em 2em;
  font-size: 1.2em;
  cursor: pointer;
}
</style>
