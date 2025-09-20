<template>
  <v-container>
    <v-card class="pa-6" elevation="8">
      <v-row justify="space-between">
    <v-col cols="auto">
      <v-card-title>Willkommen, {{ auth.user?.name }} 🎉</v-card-title>
    </v-col>
    <v-col cols="auto">
      <v-btn color="error" @click="logout">Logout</v-btn>
    </v-col>
  </v-row>

    </v-card>
    <Upload></Upload>
    <files-view></files-view>
      
  </v-container>
</template>

<script setup lang="ts">
import { useAuthStore } from '@/stores/auth'
import { useRouter } from 'vue-router'
import Upload from "@/components/Upload.vue"
import FilesView from '@/components/FilesView.vue'

const auth = useAuthStore()
const router = useRouter()

function logout() {
  auth.logout()
  router.push('/login')
}
</script>