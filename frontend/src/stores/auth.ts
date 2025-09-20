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
        this.token = data.token
        return true
      } else {
        throw new Error(data.message)
      }
    },

    // 👇 Neue Function für authentifizierte API-Requests
    async apiRequest(url: string, options: RequestInit = {}) {
      if (!this.token) {
        throw new Error('Nicht authentifiziert')
      }

      const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.token}`,
        ...options.headers // Falls du zusätzliche Headers brauchst
      }

      const res = await fetch(url, {
        ...options,
        headers
      })

      // Automatisch ausloggen bei 401 (Token abgelaufen)
      if (res.status === 401) {
        this.logout()
        throw new Error('Session abgelaufen - bitte neu einloggen')
      }

      return res
    },

    logout() {
      this.user = null
      this.token = null
    }
  }
})