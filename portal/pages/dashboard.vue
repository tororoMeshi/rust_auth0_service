<!-- pages/dashboard.vue -->
<template>
  <div class="dashboard">
    <h1>Dashboard</h1>
    <div v-if="user">
      <img :src="user.picture" alt="User Icon" style="max-width:100px; border-radius:50%;">
      <p><strong>Email:</strong> {{ user.email }}</p>
      <p><strong>Name:</strong> {{ user.name }}</p>
      <!-- 追加：チャットアプリへ移動するためのボタン -->
      <button @click="joinChat">Join Chat</button>
      <!-- 既存：ログアウトボタン -->
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
    await this.fetchUser();
  },
  methods: {
    // ユーザー情報取得 API (/api/me) を呼び出し、認証済みのユーザー情報を取得
    async fetchUser() {
      try {
        const res = await this.$axios.get('/api/me', { withCredentials: true });
        if (res && res.data && res.data.user) {
          this.user = res.data.user;
        } else {
          const errMsg = "No user info returned from API.";
          console.error("Error fetching user info:", errMsg);
          this.$router.push({ path: '/login-error', query: { error: errMsg } });
        }
      } catch (e) {
        console.error("Failed to fetch user info:", e);
        this.$router.push({ path: '/login-error', query: { error: e.message || "Unknown error" } });
      }
    },
    // ログアウト処理（認証サーバー側の /logout API を呼び出す）
    async logout() {
      try {
        await this.$axios.post('https://auth.tororomeshi.net/uniauth/logout', {}, { withCredentials: true });
      } catch (e) {
        console.error("Logout failed:", e);
      } finally {
        window.location.href = '/';
      }
    },
    // 【新規追加】チャットアプリへ遷移する処理
    joinChat() {
      // 例：Stateless Chat の部屋一覧ページへ遷移
      window.location.href = 'https://chat.tororomeshi.net/rooms.html';
    }
  }
}
</script>

<style scoped>
.dashboard {
  max-width: 600px;
  margin: 0 auto;
  padding: 2em;
  text-align: center;
}
img {
  display: block;
  margin: 0 auto 1em;
}
button {
  margin-top: 1em;
  padding: 0.8em 1.5em;
  font-size: 1em;
  cursor: pointer;
}
</style>
