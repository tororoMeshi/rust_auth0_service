<template>
  <div class="dashboard">
    <h1>Dashboard</h1>
    <div v-if="authenticated">
      <p>Authenticated</p>
      <p><strong>Internal user ID:</strong> {{ internalUserId }}</p>
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
    const authenticated = ref(false)
    const internalUserId = ref(null)

    const fetchAuthentication = async () => {
      try {
        const response = await apiClient.get('/api/me')
        if (response.data?.authenticated === true) {
          authenticated.value = true
          internalUserId.value = response.data.internal_user_id
        }
      } catch (error) {
        if (error.response?.status === 401) {
          router.replace('/')
        }
      }
    }

    const getCsrfToken = () => {
      const cookieName = '__Host-portal_csrf='
      const values = document.cookie
        .split(';')
        .map(cookie => cookie.trim())
        .filter(cookie => cookie.startsWith(cookieName))
        .map(cookie => cookie.slice(cookieName.length))

      return values.length === 1 && values[0] ? values[0] : null
    }

    const logout = async () => {
      const csrfToken = getCsrfToken()
      if (!csrfToken) {
        return
      }

      try {
        const response = await apiClient.post('/logout', undefined, {
          headers: {
            'X-CSRF-Token': csrfToken
          }
        })

        if (response.status === 204) {
          authenticated.value = false
          internalUserId.value = null
          router.replace('/')
        }
      } catch (error) {
        // Keep the current authentication state and dashboard on logout failure.
      }
    }

    const joinChat = () => {
      window.location.href = 'https://chat.tororomeshi.net/rooms.html'
    }

    onMounted(() => {
      fetchAuthentication()
    })

    return {
      authenticated,
      internalUserId,
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
button {
  margin-top: 1em;
  padding: 0.8em 1.5em;
  font-size: 1em;
  cursor: pointer;
}
</style>
