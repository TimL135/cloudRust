// ===========================================
// Hybrid Key Management: IndexedDB + Password-Fallback
// ===========================================

interface EncryptedKeyPair {
    publicKey: string;           // Base64 Public Key
    encryptedPrivateKey: string; // Passwort-verschlüsselter PKCS#8 Private Key
}

export interface EncryptedFile {
    encryptedData: string;      // Base64 verschlüsselte Datei
    iv: string;                 // Base64 IV
    fileName: string;           // Original Dateiname
    fileType: string;           // MIME-Type (z.B. "image/png")
    fileSize: number;           // Original Größe in Bytes
}
// IndexedDB Konfiguration
const KEY_DB = "cryptoKeysDB";
const KEY_STORE = "keys";

// ===========================================
// DB + Helper
// ===========================================
export function arrayBufferToBase64(buf: ArrayBuffer): string {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
export function base64ToArrayBuffer(str: string): ArrayBuffer {
    return Uint8Array.from(atob(str), c => c.charCodeAt(0)).buffer;
}
async function openDB(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(KEY_DB, 1);
        req.onupgradeneeded = () => {
            const db = req.result;
            if (!db.objectStoreNames.contains(KEY_STORE)) {
                db.createObjectStore(KEY_STORE, { keyPath: "id" });
            }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

// Speichern in IndexedDB
async function saveToIndexedDB(id: string, privateKey: CryptoKey, publicKey: string) {
    const db = await openDB();
    const tx = db.transaction(KEY_STORE, "readwrite");
    tx.objectStore(KEY_STORE).put({ id, privateKey, publicKey });
    return tx.oncomplete;
}

// Laden aus IndexedDB
export async function loadFromIndexedDB(id: string): Promise<{ privateKey: CryptoKey, publicKey: CryptoKey } | null> {
    const db = await openDB();
    const tx = db.transaction(KEY_STORE, "readonly");
    const req = tx.objectStore(KEY_STORE).get(id);

    return new Promise(async (resolve) => {
        req.onsuccess = async () => {
            const data = req.result;
            if (!data) {
                resolve(null);
                return;
            }

            // Falls publicKey als Base64 String gespeichert ist
            if (typeof data.publicKey === 'string') {
                const publicKeyCrypto = await crypto.subtle.importKey(
                    "raw",
                    base64ToArrayBuffer(data.publicKey),
                    { name: "ECDH", namedCurve: "P-256" },
                    true,
                    []
                );
                resolve({ privateKey: data.privateKey, publicKey: publicKeyCrypto });
            } else {
                // Falls schon als CryptoKey gespeichert
                resolve({ privateKey: data.privateKey, publicKey: data.publicKey });
            }
        };
        req.onerror = () => resolve(null);
    });
}

// ===========================================
// Password-Schutz (PBKDF2 + AES-GCM)
// ===========================================
async function encryptPrivateKeyWithPassword(privateKey: CryptoKey, password: string): Promise<string> {
    const passwordKey = await crypto.subtle.importKey(
        "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]
    );

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const aesKey = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
        passwordKey, { name: "AES-GCM", length: 256 }, false, ["encrypt"]
    );

    const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, pkcs8);

    const combined = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(ciphertext), salt.length + iv.length);

    return arrayBufferToBase64(combined.buffer);
}

async function decryptPrivateKeyWithPassword(encryptedBase64: string, password: string): Promise<CryptoKey> {
    const combined = new Uint8Array(base64ToArrayBuffer(encryptedBase64));
    const salt = combined.slice(0, 16);
    const iv = combined.slice(16, 28);
    const data = combined.slice(28);

    const passwordKey = await crypto.subtle.importKey(
        "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]
    );

    const aesKey = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
        passwordKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
    );

    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, data);

    return crypto.subtle.importKey(
        "pkcs8", decrypted, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]
    );
}

// ===========================================
// Hybrid KeyPair Erzeugung
// ===========================================
export async function createHybridKeyPair(userId: string, password: string): Promise<EncryptedKeyPair> {
    const keyPair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]
    );

    // Public Key exportieren (raw → Base64)
    const rawPublic = await crypto.subtle.exportKey("raw", keyPair.publicKey);
    const publicKeyBase64 = arrayBufferToBase64(rawPublic);

    // Private Key in IndexedDB speichern (non-extractable, für Komfort)
    await saveToIndexedDB(userId, keyPair.privateKey, publicKeyBase64);

    // Private Key zusätzlich mit Passwort verschlüsseln (für Recovery / DB)
    const encryptedPrivateKey = await encryptPrivateKeyWithPassword(keyPair.privateKey, password);

    return { publicKey: publicKeyBase64, encryptedPrivateKey };
}

// Hilfsmethoden: wie in deinem Code (`arrayBufferToBase64` etc.)
// Annahme: jeder User hat bereits ein Schlüsselpaar {publicKey, privateKey}

// Schritt 1: Symmetrischen AES-Key machen für die Nachricht
async function generateAESKey(): Promise<CryptoKey> {
    return crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// String mit AES verschlüsseln
async function encryptMessage(message: string, aesKey: CryptoKey): Promise<{ ciphertext: string, iv: string }> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(message);
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, encoded);
    return { ciphertext: arrayBufferToBase64(ciphertext), iv: arrayBufferToBase64(iv.buffer) };
}
// String mit AES entschl�sseln
async function decryptMessage(ciphertext: string, iv: string, aesKey: CryptoKey): Promise<string> {
    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: base64ToArrayBuffer(iv) },
        aesKey,
        base64ToArrayBuffer(ciphertext)
    );
    return new TextDecoder().decode(decrypted);
}
// AES-Key für User verschlüsseln
async function encryptKeyForUser(aesKey: CryptoKey, senderPrivateKey: CryptoKey, userPublicKey: CryptoKey): Promise<string> {
    // Shared Secret (ECDH)
    const sharedSecret = await crypto.subtle.deriveKey(
        { name: "ECDH", public: userPublicKey },
        senderPrivateKey,
        { name: "AES-KW", length: 256 }, // direkt Ableitung als AES
        true,
        ["wrapKey"]
    );
    // wrapKey = AES-Key verschlüsseln
    const wrapped = await crypto.subtle.wrapKey("raw", aesKey, sharedSecret, { name: "AES-KW" });

    return arrayBufferToBase64(wrapped)
}

export async function decryptKeyForUser(
    wrappedKeyBase64: string,
    senderPublicKey: CryptoKey,
    userPrivateKey: CryptoKey
): Promise<CryptoKey> {

    const sharedSecret = await crypto.subtle.deriveKey(
        { name: "ECDH", public: senderPublicKey },
        userPrivateKey,
        { name: "AES-KW", length: 256 },
        true,
        ["unwrapKey"]
    );

    const aesKey = await crypto.subtle.unwrapKey(
        "raw",
        base64ToArrayBuffer(JSON.parse(wrappedKeyBase64).wrappedKey.wrapped_key),
        sharedSecret,
        "AES-KW", // kein IV!
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
    return aesKey;
}

async function encryptFile(file: File, aesKey: CryptoKey): Promise<EncryptedFile> {
    // Datei als ArrayBuffer lesen
    const fileBuffer = await file.arrayBuffer();

    // IV generieren
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Verschl�sseln
    const encryptedData = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        aesKey,
        fileBuffer
    );

    return {
        encryptedData: arrayBufferToBase64(encryptedData),
        iv: arrayBufferToBase64(iv.buffer),
        fileName: file.name,
        fileType: file.type,
        fileSize: file.size
    };
}

// ===========================================
// Datei entschlüsseln (FIXED)
// ===========================================
export async function decryptFile(
    encryptedFile: EncryptedFile,
    aesKey: CryptoKey,
    iv: string,
): Promise<File> {
    // 1. IV prüfen
    const ivBuffer = base64ToArrayBuffer(iv);

    // 2. Encrypted Data von Base64 -> ArrayBuffer
    const encryptedBuffer = base64ToArrayBuffer(encryptedFile.encryptedData);

    // 3. Entschlüsseln
    const decryptedData = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ivBuffer },
        aesKey,
        encryptedBuffer
    );

    // 4. Neues File-Objekt erzeugen
    return new File([decryptedData], encryptedFile.fileName, {
        type: encryptedFile.fileType,
    });
}
// ===========================================
// Datei verschlüsseln für mehrere User
// ===========================================
export interface MultiRecipientEncryptedFile {
    encryptedFile: EncryptedFile;
    wrappedKeys: Map<string, string>;
}

export async function encryptFileForMultipleUsers(
    file: File,
    senderPrivateKey: CryptoKey,
    recipients: Array<{ userId: string; publicKey: CryptoKey }>
): Promise<MultiRecipientEncryptedFile> {
    // 1. AES-Key generieren
    const aesKey = await generateAESKey();

    // 2. Datei verschlüsseln
    const encryptedFile = await encryptFile(file, aesKey);

    // 3. AES-Key für jeden User verschlüsseln
    const wrappedKeys = new Map<string, string>();

    for (const recipient of recipients) {
        const wrapped = await encryptKeyForUser(
            aesKey,
            senderPrivateKey,
            recipient.publicKey
        );
        wrappedKeys.set(recipient.userId, wrapped);
    }

    return { encryptedFile, wrappedKeys };
}

// ===========================================
// Datei entschlüsseln als User
// ===========================================
export async function decryptFileAsUser(
    encryptedFile: EncryptedFile,
    userPrivateKey: CryptoKey,
    senderPublicKey: CryptoKey,
    wrappedKey: string,
    file_iv: string,
): Promise<File> {

    // 2. AES-Key entschlüsseln
    const aesKey = await decryptKeyForUser(
        wrappedKey,
        senderPublicKey,
        userPrivateKey
    );
    // 3. Datei entschlüsseln
    const decryptedFile = await decryptFile(encryptedFile, aesKey, file_iv);

    return decryptedFile;
}

// ===========================================
// Neuen User zu verschlüsselter Datei hinzufügen (FIXED)
// ===========================================
async function addRecipientToEncryptedFile(
    multiRecipientFile: MultiRecipientEncryptedFile,
    newRecipient: { userId: string; publicKey: CryptoKey },
    existingUserPrivateKey: CryptoKey,
    senderPublicKey: CryptoKey,
    existingUserId: string
): Promise<void> {
    // 1. AES-Key mit eigenem Private Key entschlüsseln
    const wrappedKey = multiRecipientFile.wrappedKeys.get(existingUserId);
    if (!wrappedKey) {
        throw new Error(`❌ Du hast keinen Zugriff auf diese Datei!`);
    }

    const aesKey = await decryptKeyForUser(
        wrappedKey,
        senderPublicKey,
        existingUserPrivateKey
    );

    // 2. AES-Key für neuen User verschlüsseln
    // WICHTIG: Wir nutzen UNSEREN Private Key als "Sender"
    const newWrappedKey = await encryptKeyForUser(
        aesKey,
        existingUserPrivateKey,  // Bob's Private Key wird zum "Sender"
        newRecipient.publicKey
    );

    // 3. Zur Map hinzufügen
    multiRecipientFile.wrappedKeys.set(newRecipient.userId, newWrappedKey);

    // WICHTIG: Wir müssen auch den "Sender Public Key" für Carol speichern!
    // Sonst kann Carol nicht entschlüsseln, weil sie nicht weiß, wer der Sender war

}
