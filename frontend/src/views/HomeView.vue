<template>
  <v-container>
    <v-card class="pa-6" elevation="8">
      <v-row justify="space-between">
        <v-col cols="auto">
          <v-card-title>Willkommen, {{ auth.user?.name }} 🎉</v-card-title>
        </v-col>
        <v-col cols="auto">
          <v-btn color="primary" @click="openUserModal" class="mr-2">
            Neuer User
          </v-btn>
          <v-btn color="error" @click="logout">Logout</v-btn>
        </v-col>
      </v-row>

    </v-card>
    <Upload></Upload>
    <files-view></files-view>

    <!-- User Modal -->
    <v-dialog v-model="userModal" max-width="500px">
      <v-card>
        <v-card-title>
          <span class="text-h5">Neuen User anlegen</span>
        </v-card-title>
        <v-card-text>
          <v-container>
            <v-row>
              <v-col cols="12">
                <v-text-field v-model="newUser.name" label="Name*" required
                  :error-messages="errors.name"></v-text-field>
              </v-col>
              <v-col cols="12">
                <v-text-field v-model="newUser.email" label="E-Mail*" type="email" required
                  :error-messages="errors.email"></v-text-field>
              </v-col>
              <v-col cols="12">
                <v-text-field v-model="newUser.password" label="Passwort*" type="password" required
                  :error-messages="errors.password"></v-text-field>
              </v-col>
            </v-row>
          </v-container>
        </v-card-text>
        <v-card-actions>
          <v-spacer></v-spacer>
          <v-btn color="blue darken-1" text @click="closeUserModal">
            Abbrechen
          </v-btn>
          <v-btn color="blue darken-1" text @click="createUser" :loading="loading">
            Erstellen
          </v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <v-snackbar v-model="snackbar.show" rounded="pill" vertical color="success">
      {{ snackbar.text }}
    </v-snackbar>

  </v-container>
</template>

<script setup lang="ts">
import { useAuthStore } from '@/stores/auth'
import { useRouter } from 'vue-router'
import Upload from "@/components/Upload.vue"
import FilesView from '@/components/FilesView.vue'
import { reactive, ref } from 'vue'
import { apiRequest } from '@/api'

interface NewUser {
  name: string
  email: string
  password: string
}

interface UserErrors {
  name: string[]
  email: string[]
  password: string[]
}

interface Snackbar {
  show: boolean
  color: "success" | "error"
  text: string
}

const auth = useAuthStore()
const router = useRouter()

// Modal state
const userModal = ref(false)
const loading = ref(false)

const snackbar = reactive<Snackbar>({
  show: false,
  color: "success",
  text: "",
})



const newUser = reactive<NewUser>({
  name: '',
  email: '',
  password: ''
})

const errors = reactive<UserErrors>({
  name: [],
  email: [],
  password: []
})

const openUserModal = () => {
  userModal.value = true
  resetForm()
}

const closeUserModal = () => {
  userModal.value = false
  resetForm()
}

const resetForm = () => {
  newUser.name = ''
  newUser.email = ''
  newUser.password = ''
  errors.name = []
  errors.email = []
  errors.password = []
}

const validateForm = () => {
  let isValid = true

  errors.name = []
  errors.email = []
  errors.password = []

  if (!newUser.name.trim()) {
    errors.name.push('Name ist erforderlich')
    isValid = false
  }

  if (!newUser.email.trim()) {
    errors.email.push('E-Mail ist erforderlich')
    isValid = false
  } else if (!/\S+@\S+\.\S+/.test(newUser.email)) {
    errors.email.push('Ungültige E-Mail-Adresse')
    isValid = false
  }

  if (!newUser.password.trim()) {
    errors.password.push('Passwort ist erforderlich')
    isValid = false
  } else if (newUser.password.length < 5) {
    errors.password.push('Passwort muss mindestens 5 Zeichen haben')
    isValid = false
  }

  return isValid
}

const createUser = async () => {
  if (!validateForm()) return

  loading.value = true

  try {
    apiRequest("/api/auth/register", {}, "POST", newUser)

    // Erfolg - Modal schließen
    closeUserModal()
    snackbar.color = "success"
    snackbar.text = "User erfolgreich angelegt"
    snackbar.show = true

  } catch (error) {
    snackbar.color = "error"
    snackbar.text = "Fehler beim User anlegen"
    snackbar.show = true
    // Error handling
  } finally {
    loading.value = false
  }
}

function logout() {
  auth.logout()
  router.push('/login')
}
</script>