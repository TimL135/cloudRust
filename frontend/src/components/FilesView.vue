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
                <v-text-field v-model="searchQuery" label="Nach Dateiname suchen..." prepend-inner-icon="mdi-magnify"
                    clearable variant="outlined" density="compact" class="mb-4" />
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
                        <v-btn icon color="error" variant="text" @click="showDeleteConfirmation(item)">
                            <v-icon>mdi-delete</v-icon>
                        </v-btn>
                    </template>
                </v-data-table>

                <!-- Bestätigungs-Modal für Löschen -->
                <v-dialog v-model="deleteDialog" max-width="400">
                    <v-card>
                        <v-card-title class="text-h6">
                            Datei löschen
                        </v-card-title>
                        <v-card-text>
                            Möchten Sie die Datei "{{ selectedFile?.original_filename }}" wirklich löschen?
                            Diese Aktion kann nicht rückgängig gemacht werden.
                        </v-card-text>
                        <v-card-actions>
                            <v-spacer></v-spacer>
                            <v-btn color="grey" variant="text" @click="deleteDialog = false">
                                Abbrechen
                            </v-btn>
                            <v-btn color="error" variant="text" @click="confirmDelete">
                                Löschen
                            </v-btn>
                        </v-card-actions>
                    </v-card>
                </v-dialog>
            </v-col>
        </v-row>
    </v-card>
</template>

<script setup lang="ts">
import { useAuthStore } from "@/stores/auth"
import { apiRequest } from "@/api"
import { ref, onMounted, computed } from "vue"

interface FileItem {
    id: number
    original_filename: string
}
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
const deleteDialog = ref(false)
const selectedFile = ref<FileItem | null>(null)
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
    {
        title: "Hochgeladen am",
        key: "created_at",
        value: (f: FileInfo) => {
            const utcString = f.created_at.endsWith("Z") ? f.created_at : f.created_at + "Z";
            return new Date(utcString).toLocaleString("de-DE", {
                dateStyle: "medium",
                timeStyle: "short"
            });
        }
    },
    { title: "Aktionen", key: "actions", sortable: false },
]

// Files laden
async function fetchFiles() {
    loading.value = true
    error.value = ""
    try {
        const res = await apiRequest('/api/files')
        if (!res.ok) throw new Error("Fehler beim Laden der Dateien")
        const data = await res.json()
        files.value = data.files
    } catch (e: any) {
        error.value = e.message ?? "Unbekannter Fehler"
        console.log(e)
    } finally {
        loading.value = false
    }
}

// File Download
async function downloadFile(id: number, filename: string) {
    try {
        const res = await apiRequest(`/api/files/${id}/download`)
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

async function deleteFile(id: number) {
    try {
        const res = await apiRequest(`/api/files/${id}/delete`)
        if (!res.ok) throw new Error("Fehler beim Loschen")
    } catch (e: any) {
        alert(e.message ?? "Download fehlgeschlagen")
    }
}

const showDeleteConfirmation = (item: FileItem) => {
    selectedFile.value = item
    deleteDialog.value = true
}

const confirmDelete = () => {
    if (selectedFile.value) {
        deleteFile(selectedFile.value.id)
        deleteDialog.value = false
        selectedFile.value = null
    }
}

const socket = new WebSocket("ws://localhost:3000/ws?user_id=" + authStore.$state.user?.id);

socket.onmessage = () => {
    fetchFiles();
};

onMounted(fetchFiles)
</script>