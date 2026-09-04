<template>
  <div class="login-page">
    <h1>Welcome to the Portal</h1>
    <button @click="login">Login with Google</button>
  </div>
</template>

<script>
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'
import apiClient from '../utils/axios'

export default {
  name: 'HomePage',
  setup() {
    const router = useRouter()

    const login = () => {
      window.location.assign('/login')
    }

    const checkAuthentication = async () => {
      try {
        const response = await apiClient.get('/api/me')
        if (response.data?.authenticated === true) {
          router.replace('/dashboard')
        }
      } catch (error) {
        if (error.response?.status === 401) {
          return
        }
      }
    }

    onMounted(checkAuthentication)

    return {
      login
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
