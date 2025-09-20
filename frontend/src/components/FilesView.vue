<template>
    <v-card class="pa-6 mt-6" elevation="8">
        <v-row>
            <v-col>
                <h2 class="mb-4">📁 Meine Dateien</h2>
            </v-col>
        </v-row>

        <!-- Suchleiste -->
        <v-row>
            <v-col>
                <v-text-field
                    v-model="searchQuery"
                    label="Nach Dateiname suchen..."
                    prepend-inner-icon="mdi-magnify"
                    clearable
                    variant="outlined"
                    density="compact"
                    class="mb-4"
                />
            </v-col>
        </v-row>

        <!-- Progress / Fehler -->
        <v-row v-if="loading">
            <v-col class="text-center">
                <v-progress-circular indeterminate color="primary" />
            </v-col>
        </v-row>
        <v-row v-if="error">
            <v-col class="text-center">
                <v-alert type="error" dense>{{ error }}</v-alert>
            </v-col>
        </v-row>

        <!-- Data Table -->
        <v-row>
            <v-col>
                <v-data-table :headers="headers" :items="filteredFiles" :items-per-page="10" class="elevation-1">
                    <template #item.actions="{ item }">
                        <v-btn icon color="primary" variant="text"
                            @click="downloadFile(item.id, item.original_filename)">
                            <v-icon>mdi-download</v-icon>
                        </v-btn>
                    </template>
                </v-data-table>
            </v-col>
        </v-row>
    </v-card>
</template>

<script setup lang="ts">
import { useAuthStore } from "@/stores/auth"
import { ref, onMounted, computed } from "vue"
const authStore = useAuthStore()

interface FileInfo {
    id: number
    original_filename: string
    file_size: number
    mime_type?: string
    is_public: boolean
    created_at: string
}

const files = ref<FileInfo[]>([])
const loading = ref(false)
const error = ref("")
const searchQuery = ref("")
const filteredFiles = computed(() => {
    if (!searchQuery.value) return files.value
    return files.value.filter(file => 
        file.original_filename.toLowerCase().includes(searchQuery.value.toLowerCase())
    )
})

const headers = [
    { title: "Dateiname", key: "original_filename" },
    { title: "Größe (KB)", key: "file_size", value: (f: FileInfo) => (f.file_size / 1024).toFixed(1) },
    { title: "MIME", key: "mime_type" },
    { title: "Hochgeladen am", key: "created_at" },
    { title: "Aktionen", key: "actions", sortable: false },
]

// Files laden
async function fetchFiles() {
    loading.value = true
    error.value = ""
    try {
        const res = await authStore.apiRequest('/api/files')
        if (!res.ok) throw new Error("Fehler beim Laden der Dateien")
        const data = await res.json()
        files.value = data.files
    } catch (e: any) {
        error.value = e.message ?? "Unbekannter Fehler"
    } finally {
        loading.value = false
    }
}

// File Download
async function downloadFile(id: number, filename: string) {
    try {
        const res = await fetch(`/api/files/${id}/download`)
        if (!res.ok) throw new Error("Fehler beim Download")

        const blob = await res.blob()
        const url = window.URL.createObjectURL(blob)
        const link = document.createElement("a")
        link.href = url
        link.setAttribute("download", filename)
        document.body.appendChild(link)
        link.click()
        link.parentNode?.removeChild(link)
        window.URL.revokeObjectURL(url)
    } catch (e: any) {
        alert(e.message ?? "Download fehlgeschlagen")
    }
}

onMounted(fetchFiles)
</script>