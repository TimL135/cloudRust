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
            const private_key = await loadUserPrivateKey(this.user.id + "", this.user.encrypted_private_key)
            await testWithExistingUserA(this.user.id + "", this.user.public_key, private_key, "hello world")
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
          const private_key = await loadUserPrivateKey(this.user.id + "", this.user.encrypted_private_key, password)
          await testWithExistingUserA(this.user.id + "", this.user.public_key, private_key, "hello world")
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
async function saveToIndexedDB(id: string, privateKey: CryptoKey) {
  const db = await openDB();
  const tx = db.transaction(KEY_STORE, "readwrite");
  tx.objectStore(KEY_STORE).put({ id, privateKey });
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
  await saveToIndexedDB(userId, keyPair.privateKey);

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
    const private_key = await decryptPrivateKeyWithPassword(encryptedPrivateKey, password)
    await saveToIndexedDB(userId, private_key)
    return private_key;
  }

  throw new Error("Kein Private Key verfügbar (IndexedDB leer, Passwort nicht gegeben)");
}

/**
 * Hybrid-Test: User A mit existierenden Keys, User B wird neu erstellt
 * 
 * @param userAId - User A's ID
 * @param userAPublicKey - User A's Public Key (Base64, aus DB)
 * @param userAEncryptedPrivateKey - User A's verschlüsselter Private Key (Base64, aus DB)
 * @param userAPassword - User A's Passwort (zum Entschlüsseln des Private Keys)
 * @param userAMessage - Die Nachricht, die A an B schicken will
 */
async function testWithExistingUserA(
  userAId: string,
  userAPublicKey: string,
  userAPrivateKey: CryptoKey,
  userAMessage: string,
) {
  console.log("🔐 Hybrid-Test: User A (existierend) → User B (neu)");
  console.log("=".repeat(60));
  console.log(`User A ID: ${userAId}`);
  console.log(`User A Public Key (gekürzt): ${userAPublicKey.substring(0, 40)}...`);
  console.log(`Nachricht: "${userAMessage}"`);
  console.log("=".repeat(60));

  // ============================================
  // 1. User A: Private Key laden
  // ============================================


  // ============================================
  // 2. User B: Komplett neu erstellen
  // ============================================
  const userBId = "userB_" + Date.now(); // Eindeutige ID
  const userBPassword = "AutoGeneratedPass_" + Math.random().toString(36);

  console.log(`📝 User B wird neu erstellt (ID: ${userBId})...`);
  const userBKeyPairData = await createHybridKeyPair(userBId, userBPassword);

  console.log("✅ User B KeyPair erstellt");
  console.log(`   User B ID: ${userBId}`);
  console.log(`   User B Public Key (gekürzt): ${userBKeyPairData.publicKey.substring(0, 40)}...`);

  // Simuliere Server-DB
  const SERVER_DB = {
    userB: {
      publicKey: userBKeyPairData.publicKey,
      encryptedPrivateKey: userBKeyPairData.encryptedPrivateKey
    }
  };

  // ============================================
  // 3. User A verschlüsselt Nachricht für User B
  // ============================================
  const userBPublic = await importPublicKey(SERVER_DB.userB.publicKey);
  const sharedKeyA = await crypto.subtle.deriveKey(
    { name: "ECDH", public: userBPublic },
    userAPrivateKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    sharedKeyA,
    new TextEncoder().encode(userAMessage)
  );

  console.log("✅ User A hat Nachricht verschlüsselt");
  console.log("   Original:", userAMessage);
  console.log("   IV (Base64):", arrayBufferToBase64(iv.buffer));
  console.log("   Ciphertext (Base64, gekürzt):", arrayBufferToBase64(ciphertext).substring(0, 40) + "...");

  // Verschlüsselte Nachricht speichern
  const encryptedMessage = {
    from: userAId,
    to: userBId,
    iv: arrayBufferToBase64(iv.buffer),
    ciphertext: arrayBufferToBase64(ciphertext),
    senderPublicKey: userAPublicKey
  };

  // ============================================
  // 4. User B entschlüsselt Nachricht von User A
  // ============================================
  const userBPrivateKey = await loadUserPrivateKey(userBId, SERVER_DB.userB.encryptedPrivateKey);
  const userAPublicImported = await importPublicKey(encryptedMessage.senderPublicKey);

  const sharedKeyB = await crypto.subtle.deriveKey(
    { name: "ECDH", public: userAPublicImported },
    userBPrivateKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const ivFromDB = new Uint8Array(base64ToArrayBuffer(encryptedMessage.iv));
  const ciphertextFromDB = base64ToArrayBuffer(encryptedMessage.ciphertext);

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ivFromDB },
    sharedKeyB,
    ciphertextFromDB
  );

  const decryptedMessage = new TextDecoder().decode(decrypted);
  console.log("🔓 User B: Nachricht entschlüsselt:", decryptedMessage);

  // ============================================
  // 5. Validierung
  // ============================================
  if (decryptedMessage === userAMessage) {
    console.log("\n✅ ✅ ✅ TEST BESTANDEN!");
    console.log(`   User B konnte die Nachricht von User A erfolgreich entschlüsseln.`);
    console.log(`   Original:     "${userAMessage}"`);
    console.log(`   Entschlüsselt: "${decryptedMessage}"`);
  } else {
    console.error("\n❌ TEST FEHLGESCHLAGEN!");
    console.error(`   Erwartet: "${userAMessage}"`);
    console.error(`   Erhalten: "${decryptedMessage}"`);
  }

  console.log("=".repeat(60));

  // Rückgabe für weitere Verwendung
  return {
    userA: {
      id: userAId,
      publicKey: userAPublicKey
    },
    userB: {
      id: userBId,
      publicKey: userBKeyPairData.publicKey,
      encryptedPrivateKey: userBKeyPairData.encryptedPrivateKey,
      password: userBPassword
    },
    encryptedMessage,
    decryptedMessage
  };
}

// ============================================
// Hilfsfunktion: importPublicKey
// ============================================
async function importPublicKey(publicKeyBase64: string): Promise<CryptoKey> {
  const raw = base64ToArrayBuffer(publicKeyBase64);
  return crypto.subtle.importKey(
    "raw",
    raw,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
}

