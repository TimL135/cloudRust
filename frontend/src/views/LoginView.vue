<template>
  <v-container class="d-flex align-center justify-center" style="height: 100vh;">
    <v-card class="pa-6" width="400" elevation="8">
      <v-card-title class="text-center">🔐 Login</v-card-title>
      <v-card-text>
        <v-text-field
          v-model="email"
          label="E-Mail"
          type="email"
          variant="outlined"
          class="mb-3"
        />
        <v-text-field
          v-model="password"
          label="Passwort"
          type="password"
          variant="outlined"
          class="mb-3"
        />
        <v-btn block color="primary" :loading="loading" @click="doLogin">Einloggen</v-btn>
        <v-alert v-if="error" type="error" class="mt-3">{{ error }}</v-alert>
      </v-card-text>
    </v-card>
  </v-container>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const email = ref('')
const password = ref('')
const error = ref('')
const loading = ref(false)

const auth = useAuthStore()
const router = useRouter()

async function doLogin() {
  loading.value = true
  error.value = ''
  try {
    await auth.login(email.value, password.value)
    router.push('/')
  } catch (e: any) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}
</script>