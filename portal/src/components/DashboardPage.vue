<template>
  <div class="dashboard">
    <h1>Dashboard</h1>
    <div v-if="user">
      <img :src="user.picture" alt="User Icon" style="max-width:100px; border-radius:50%;">
      <p><strong>Email:</strong> {{ user.email }}</p>
      <p><strong>Name:</strong> {{ user.name }}</p>
      <button @click="joinChat">Join Chat</button>
      <button @click="logout">Logout</button>
    </div>
    <div v-else>
      <p>Loading user info...</p>
    </div>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import apiClient from '../utils/axios'

export default {
  name: 'DashboardPage',
  setup() {
    const router = useRouter()
    const user = ref(null)

    const fetchUser = async () => {
      try {
        const res = await apiClient.get('/api/me')
        if (res && res.data && res.data.user) {
          user.value = res.data.user
        } else {
          const errMsg = "No user info returned from API."
          console.error("Error fetching user info:", errMsg)
          router.push({ path: '/', query: { error: 'Authentication required' } })
        }
      } catch (e) {
        console.error("Failed to fetch user info:", e)
        router.push({ path: '/', query: { error: 'Authentication required' } })
      }
    }

    const logout = async () => {
      try {
        await apiClient.post('https://auth.tororomeshi.net/auth/logout')
      } catch (e) {
        console.error("Logout failed:", e)
      } finally {
        window.location.href = '/'
      }
    }

    const joinChat = () => {
      window.location.href = 'https://chat.tororomeshi.net/rooms.html'
    }

    onMounted(() => {
      fetchUser()
    })

    return {
      user,
      logout,
      joinChat
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
