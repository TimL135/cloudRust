<template>
  <v-container>
    <v-card class="pa-6" elevation="8">
      <v-card-title>Willkommen, {{ auth.user?.name }} 🎉</v-card-title>
      <v-card-subtitle>Deine Rolle: {{ auth.user?.role }}</v-card-subtitle>
      <v-card-text>
        <p>Hier kannst du Dateien hochladen und verwalten 🚀</p>
      </v-card-text>
      <v-btn color="error" @click="logout">Logout</v-btn>
    </v-card>
  </v-container>
</template>

<script setup lang="ts">
import { useAuthStore } from '@/stores/auth'
import { useRouter } from 'vue-router'

const auth = useAuthStore()
const router = useRouter()

function logout() {
  auth.logout()
  router.push('/login')
}
</script>