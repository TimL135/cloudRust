import { defineStore } from 'pinia'

interface User {
  id: number
  name: string
  email: string
  role: string
}

export const useAuthStore = defineStore('auth', {
  state: () => ({
    user: null as User | null,
    token: null as string | null
  }),
  getters: {
    isAuthenticated: (state) => !!state.user
  },
  actions: {
    async login(email: string, password: string) {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      })
      const data = await res.json()

      if (data.success) {
        this.user = data.user
        this.token = "dummy-jwt" // später JWT oder Session
        return true
      } else {
        throw new Error(data.message)
      }
    },
    logout() {
      this.user = null
      this.token = null
    }
  }
})