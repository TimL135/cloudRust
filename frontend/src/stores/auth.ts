import { apiRequest } from "@/api";
import { defineStore } from "pinia";

interface User {
  id: number;
  name: string;
  email: string;
  role: string;
}

export const useAuthStore = defineStore("auth", {
  state: () => ({
    user: null as User | null,
  }),
  getters: {
    isAuthenticated: (state) => !!state.user,
  },
  actions: {
    async auth_check() {
      try {
        let user = await apiRequest("/api/auth/auth_check", {}, "GET")
        this.user = user as unknown as User;
        return true
      } catch {
        return false
      }
    },
    async login(email: string, password: string) {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();

      if (data.success) {
        this.user = data.user;
        return true;
      } else {
        throw new Error(data.message);
      }
    },

    logout() {
      this.user = null;
    },
  },
});
