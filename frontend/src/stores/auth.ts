import { apiRequest } from "@/api";
import { createHybridKeyPair } from "@/cryptoUtils";
import { defineStore } from "pinia";

interface User {
  id: number;
  name: string;
  email: string;
  role: string;
  public_key: string
  encrypted_private_key: string
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
        let res = await apiRequest("/api/auth/auth_check", {}, "GET")
        if (res.ok) {
          let data = await res.json()
          this.user = data.user
          if (this.user) {
            return true
          }
          return false
        }
        return false
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
        if (!this.user) throw new Error("Login Fehler")
        if (this.user.public_key == "_public_key") {
          const { publicKey, encryptedPrivateKey } = await createHybridKeyPair(this.user.id + "", password)
          await fetch("/api/auth/update_keys", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ public_key: publicKey, encrypted_private_key: encryptedPrivateKey }),
          });
          return true
        }
        else {
          return true;
        }


      } else {
        throw new Error(data.message);
      }
    },

    logout() {
      this.user = null;
    },
  },
});

