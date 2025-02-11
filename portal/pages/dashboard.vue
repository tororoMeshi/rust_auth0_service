<template>
  <div class="dashboard">
    <h1>Dashboard</h1>
    <div v-if="user">
      <img :src="user.picture" alt="User Icon" style="max-width:100px; border-radius:50%;">
      <p><strong>Email:</strong> {{ user.email }}</p>
      <p><strong>Name:</strong> {{ user.name }}</p>
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
    async logout() {
      try {
        await this.$axios.post('https://auth.tororomeshi.net/uniauth/logout', {}, { withCredentials: true });
      } catch (e) {
        console.error("Logout failed:", e);
      } finally {
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
