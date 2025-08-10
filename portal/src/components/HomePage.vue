<template>
  <div class="login-page">
    <h1>Welcome to the Portal</h1>
    <button @click="login">Login with Google</button>
    <button @click="goToDashboard">Go to Dashboard</button>
  </div>
</template>

<script>
import { useRouter } from 'vue-router'

export default {
  name: 'HomePage',
  setup() {
    const router = useRouter()

    const login = () => {
      const currentUrl = window.location.href
      window.location.href = "https://auth.tororomeshi.net/auth/google?redirect=" + encodeURIComponent(currentUrl)
    }

    const goToDashboard = () => {
      router.push('/dashboard')
    }

    return {
      login,
      goToDashboard
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