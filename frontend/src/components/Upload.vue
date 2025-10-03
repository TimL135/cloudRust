<template>
    <v-card class="pa-6 mt-6" elevation="8">
        <v-card-title class="text-h5 font-weight-bold">
            <v-icon start size="32">mdi-cloud-upload</v-icon>
            Dateien hochladen
        </v-card-title>

        <v-divider />

        <v-card-text>
            <!-- Drop Area -->
            <div class="upload-area pa-8 text-center mb-8" :class="{ 'drag-over': isDragOver }" @drop="handleDrop"
                @dragover.prevent="isDragOver = true" @dragleave="isDragOver = false">
                <v-icon size="80" color="primary" class="mb-3">
                    {{ isDragOver ? 'mdi-cloud-download' : 'mdi-cloud-upload-outline' }}
                </v-icon>
                <h3 class="text-h6 mb-2">
                    {{ isDragOver ? 'Dateien hier ablegen' : 'Dateien hochladen' }}
                </h3>
                <p class="mb-4 text-grey">
                    Ziehe Dateien hierher oder klicke auf den Button
                </p>

                <v-btn color="primary" size="large" @click="($refs.fileInput as HTMLInputElement).click()">
                    <v-icon start>mdi-file-plus</v-icon>
                    Dateien auswählen
                </v-btn>
                <input ref="fileInput" type="file" multiple class="d-none" @change="handleFileSelect" />
            </div>

            <!-- Datei Liste -->
            <v-list v-if="files.length > 0" lines="two">
                <v-list-item v-for="(file, i) in files" :key="i" rounded="lg" class="mb-2">
                    <template #prepend>
                        <v-avatar :color="getFileColor(file.file.encryptedFile.fileType)" size="40">
                            <v-icon color="white">{{ getFileIcon(file.file.encryptedFile.fileType) }}</v-icon>
                        </v-avatar>
                    </template>

                    <v-list-item-title>{{ file.file.encryptedFile.fileName }}</v-list-item-title>
                    <v-list-item-subtitle>
                        {{ formatFileSize(file.file.encryptedFile.fileSize) }}
                    </v-list-item-subtitle>

                    <template #append>
                        <v-btn icon="mdi-close" size="small" variant="text" @click="removeFile(i)" />
                    </template>
                </v-list-item>
            </v-list>

            <div v-if="files.length > 0" class="text-center mt-6">
                <v-btn color="success" size="large" class="mr-3" @click="uploadFiles">
                    <v-icon start>mdi-upload</v-icon>
                    Hochladen
                </v-btn>
                <v-btn color="error" variant="outlined" @click="clearFiles">
                    <v-icon start>mdi-delete</v-icon>
                    Alle entfernen
                </v-btn>
            </div>
        </v-card-text>
    </v-card>
</template>

<script setup lang="ts">
import { arrayBufferToBase64, base64ToArrayBuffer, encryptFileForMultipleUsers, MultiRecipientEncryptedFile, } from "@/cryptoUtils";
import { useAuthStore } from "@/stores/auth";
import { ref } from "vue";

interface UploadFile {
    sender_public_key: string;
    file: MultiRecipientEncryptedFile;
}

const files = ref<UploadFile[]>([]);
const isDragOver = ref(false);
const authStore = useAuthStore()

const handleDrop = (e: DragEvent) => {
    e.preventDefault();
    isDragOver.value = false;
    if (e.dataTransfer?.files) {
        addFiles(Array.from(e.dataTransfer.files));
    }
};

const handleFileSelect = (e: Event) => {
    const target = e.target as HTMLInputElement;
    if (target.files) addFiles(Array.from(target.files));
};
function mapToObject(map: Map<string, string>): Record<string, string> {
    return Object.fromEntries(map);
}
const addFiles = async (list: File[]) => {
    const keyPair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]
    );
    const rawPublic = await crypto.subtle.exportKey("raw", keyPair.publicKey);
    const publicKeyBase64 = arrayBufferToBase64(rawPublic);
    const userArray = [{
        userId: authStore.user!.id + "", publicKey: await crypto.subtle.importKey(
            "raw",
            base64ToArrayBuffer(authStore.user!.public_key + ""),
            { name: "ECDH", namedCurve: "P-256" },
            true,
            []
        )
    }]
    list.forEach(async (f) => {
        let encryptedFile = await encryptFileForMultipleUsers(f, keyPair.privateKey, userArray)
        encryptedFile.wrappedKeys = mapToObject(encryptedFile.wrappedKeys) as any
        const file: UploadFile = {
            sender_public_key: publicKeyBase64,
            file: encryptedFile,
        };
        files.value.push(file);
    });
};

const removeFile = (i: number) => {
    files.value.splice(i, 1);
};

const clearFiles = () => {
    files.value = [];
};

const uploadFiles = async () => {
    // Falls nichts ausgewählt
    if (!files.value || files.value.length === 0) {
        throw new Error("Bitte mindestens eine Datei auswählen")
    }

    // FormData zusammenbauen
    const formData = new FormData()
    for (const file of files.value) {
        formData.append("file", JSON.stringify({
            ...file.file,
            wrappedKeys: file.file.wrappedKeys
        }));
        formData.append("sender_public_key", file.sender_public_key)
    }

    // API Call machen
    const res = await fetch("/api/upload", {
        method: "POST",
        body: formData,
        // Keine Content-Type setzen → Browser macht "multipart/form-data" automatisch
    })

    if (!res.ok) {
        throw new Error("Upload fehlgeschlagen")
    }

    clearFiles()

    const data = await res.json()

    return data
}

const formatFileSize = (bytes: number) => {
    if (!bytes) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
};

const getFileIcon = (type: string) => {
    if (type.startsWith("image/")) return "mdi-file-image";
    if (type.startsWith("video/")) return "mdi-file-video";
    if (type.startsWith("audio/")) return "mdi-file-music";
    if (type.includes("pdf")) return "mdi-file-pdf-box";
    return "mdi-file";
};

const getFileColor = (type: string) => {
    if (type.startsWith("image/")) return "green";
    if (type.startsWith("video/")) return "red";
    if (type.startsWith("audio/")) return "deep-purple";
    if (type.includes("pdf")) return "error";
    return "grey";
};
</script>

<style scoped>
.upload-area {
    border: 2px dashed #1976d2;
    border-radius: 12px;
    transition: 0.3s ease;
}

.upload-area.drag-over {
    border-color: #4caf50;
    background: #f1f8e9;
}
</style>