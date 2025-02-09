<template>
    <div class="dashboard">
      <h1>Dashboard</h1>
      <div v-if="user">
        <p>Email: {{ user.email }}</p>
        <p>Name: {{ user.name }}</p>
        <button @click="logout">Logout</button>
      </div>
      <div v-else>
        <p>Loading user info...</p>
      </div>
    </div>
  </template>
  
  <script>
  export default {
    data() {
      return {
        user: null
      }
    },
    async mounted() {
      try {
        // 認証状態確認 API を呼び出す（Cookie は HttpOnly だが、サーバ側で検証）
        const res = await this.$axios.get('/api/me', { withCredentials: true });
        if (res && res.data && res.data.user) {
          this.user = res.data.user;
        } else {
          this.user = null;
        }
      } catch (e) {
        console.error("Failed to fetch user info:", e);
        this.user = null;
      }
    },
    methods: {
      async logout() {
        try {
          // uniauth の /logout エンドポイントにログアウトリクエストを送信
          await this.$axios.post('https://auth.tororomeshi.net/uniauth/logout', {}, { withCredentials: true });
        } catch (e) {
          console.error("Logout failed:", e);
        } finally {
          // ログアウト後はトップページへリダイレクト
          window.location.href = '/';
        }
      }
    }
  }
  </script>
  
  <style scoped>
  .dashboard {
    max-width: 600px;
    margin: 0 auto;
    text-align: center;
  }
  </style>
  