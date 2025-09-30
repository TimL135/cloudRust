import { apiRequest } from "@/api";
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
            loadUserPrivateKey(this.user.id + "", this.user.encrypted_private_key)
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
          console.log(await loadUserPrivateKey(this.user.id + "", this.user.encrypted_private_key, password + ""))
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

// ===========================================
// Hybrid Key Management: IndexedDB + Password-Fallback
// ===========================================

interface EncryptedKeyPair {
  publicKey: string;           // Base64 Public Key
  encryptedPrivateKey: string; // Passwort-verschlüsselter PKCS#8 Private Key
}

// IndexedDB Konfiguration
const KEY_DB = "cryptoKeysDB";
const KEY_STORE = "keys";

// ===========================================
// DB + Helper
// ===========================================
function arrayBufferToBase64(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function base64ToArrayBuffer(str: string): ArrayBuffer {
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
async function saveToIndexedDB(id: string, privateKey: CryptoKey, publicKeyBase64: string) {
  const db = await openDB();
  const tx = db.transaction(KEY_STORE, "readwrite");
  tx.objectStore(KEY_STORE).put({ id, privateKey, publicKey: publicKeyBase64 });
  return tx.oncomplete;
}

// Laden aus IndexedDB
async function loadFromIndexedDB(id: string): Promise<{ privateKey: CryptoKey, publicKey: string } | null> {
  const db = await openDB();
  const tx = db.transaction(KEY_STORE, "readonly");
  const data = await tx.objectStore(KEY_STORE).get(id);
  return new Promise(resolve => {
    tx.oncomplete = () => resolve(data.result || null);
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

// ===========================================
// Hybrid Login: Cookie-Login (IndexedDB) + Fallback (Passwort)
// ===========================================
async function loadUserPrivateKey(userId: string, encryptedPrivateKey: string, password?: string): Promise<CryptoKey> {
  // 1. Versuche IndexedDB (Cookie-Login)
  const fromIndexedDB = await loadFromIndexedDB(userId);
  if (fromIndexedDB?.privateKey) {
    console.log("✅ Private Key aus IndexedDB geladen (kein Passwort nötig)");
    return fromIndexedDB.privateKey;
  }

  // 2. Fallback: aus DB mit Passwort entschlüsseln
  if (password) {
    console.log("⚠️ Private Key nicht in IndexedDB → Entschlüsselung mit Passwort");
    return await decryptPrivateKeyWithPassword(encryptedPrivateKey, password);
  }

  throw new Error("Kein Private Key verfügbar (IndexedDB leer, Passwort nicht gegeben)");
}

// ===========================================
// Test: Hybrid Key Management
// ===========================================
async function testHybrid() {
  console.log("🔐 Starte Hybrid-Test...");

  const userId = "userA";
  const password = "TopSecret123!";

  // 1. User registriert sich
  const keyPairData = await createHybridKeyPair(userId, password);
  console.log("✅ KeyPair erzeugt");
  console.log("   Public Key:", keyPairData.publicKey.substring(0, 40) + "...");
  console.log("   Encrypted Private Key:", keyPairData.encryptedPrivateKey.substring(0, 40) + "...");

  // Simuliere: Speichere in „Server-DB“
  const SERVER_DB = {
    publicKey: keyPairData.publicKey,
    encryptedPrivateKey: keyPairData.encryptedPrivateKey
  };

  // 2. Cookie-Login: Hole Private Key aus IndexedDB (kein Passwort)
  await loadUserPrivateKey(userId, SERVER_DB.encryptedPrivateKey);
  console.log("✅ Zugriff per Cookie-Login → Private Key aus IndexedDB verfügbar");

  // 3. Simuliere Geräteverlust: Lösche IndexedDB
  const db = await openDB();
  db.close();
  indexedDB.deleteDatabase(KEY_DB);
  console.log("💥 IndexedDB gelöscht!");

  // 4. Fallback-Login mit Passwort
  await loadUserPrivateKey(userId, SERVER_DB.encryptedPrivateKey, password);
  console.log("✅ Zugriff per Passwort-Fallback erfolgreich");

}

// Test starten
testHybrid();
