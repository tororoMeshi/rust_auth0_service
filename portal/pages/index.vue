<template>
  <div class="login-page">
    <h1>Welcome to the Portal</h1>
    <button @click="login">Login with Google</button>
  </div>
</template>

<script>
export default {
  methods: {
    login() {
      // ログイン前のリダイレクト先を指定して、rust-auth0-service の /auth/google へリダイレクト
      window.location.href = "https://auth.tororomeshi.net/auth/google?redirect=/dashboard";
    }
  }
}
</script>

<style scoped>
.login-page {
  text-align: center;
  margin-top: 50px;
}
</style>
