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
          return true
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
        if (this.user) {
          if (this.user.public_key == "_public_key") {
            const { publicKey, encryptedPrivateKey } = await createAndEncryptKeyPair(password)
            await fetch("/api/auth/update_keys", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ public_key: publicKey, encrypted_private_key: encryptedPrivateKey }),
            });
            return true
          }
          else {
            console.log(key_test({ publicKey: this.user.public_key, encryptedPrivateKey: this.user.encrypted_private_key }, password))
            return true;
          }
        }
        throw new Error("Login Fehler")
      } else {
        throw new Error(data.message);
      }
    },

    logout() {
      this.user = null;
    },
  },
});

// Types für die Krypto-Operationen
interface EncryptedKeyPair {
  publicKey: string;           // Base64-encoded raw public key
  encryptedPrivateKey: string; // Base64-encoded encrypted PKCS#8 private key
}

interface DecryptionError extends Error {
  code?: string;
  message: string;
}

// 1. Private Key mit Passwort verschlüsseln (für Server-Speicherung)
async function encryptPrivateKeyWithPassword(
  privateKey: CryptoKey,
  password: string
): Promise<string> {
  try {
    // Passwort zu AES-Schlüssel ableiten mit PBKDF2
    const passwordKey: CryptoKey = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    // Zufälliges Salt generieren
    const salt: Uint8Array = crypto.getRandomValues(new Uint8Array(16));

    // AES-Schlüssel aus Passwort ableiten
    const derivedKey: CryptoKey = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: 100000, // 100k Iterationen für Sicherheit
        hash: "SHA-256"
      } as Pbkdf2Params,
      passwordKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"]
    );

    // Private Key zu ArrayBuffer exportieren
    const privateKeyBuffer: ArrayBuffer = await crypto.subtle.exportKey("pkcs8", privateKey);

    // IV für AES-GCM generieren
    const iv: Uint8Array = crypto.getRandomValues(new Uint8Array(12));

    // Private Key verschlüsseln
    const encryptedPrivateKey: ArrayBuffer = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv } as AesGcmParams,
      derivedKey,
      privateKeyBuffer
    );

    // Salt + IV + verschlüsselter Key kombinieren
    const combined: Uint8Array = new Uint8Array(
      salt.length + iv.length + encryptedPrivateKey.byteLength
    );
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(encryptedPrivateKey), salt.length + iv.length);

    // Als Base64 für Server-Speicherung zurückgeben
    return btoa(String.fromCharCode(...combined));
  } catch (error) {
    throw new Error(`Encryption failed: ${(error as Error).message}`);
  }
}

// 2. Private Key mit Passwort entschlüsseln (vom Server laden)
async function decryptPrivateKeyWithPassword(
  encryptedPrivateKeyBase64: string,
  password: string
): Promise<CryptoKey> {
  try {
    // Base64 zu ArrayBuffer
    const combined: Uint8Array = new Uint8Array(
      atob(encryptedPrivateKeyBase64)
        .split('')
        .map(char => char.charCodeAt(0))
    );

    // Salt, IV und verschlüsselte Daten extrahieren
    const salt: Uint8Array = combined.slice(0, 16);
    const iv: Uint8Array = combined.slice(16, 28);
    const encryptedData: Uint8Array = combined.slice(28);

    // Passwort zu AES-Schlüssel ableiten
    const passwordKey: CryptoKey = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    const derivedKey: CryptoKey = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: 100000, // Gleiche Iterationen wie beim Verschlüsseln
        hash: "SHA-256"
      } as Pbkdf2Params,
      passwordKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );

    // Private Key entschlüsseln
    const encryptedDataBuffer: ArrayBuffer = uint8ArrayToArrayBuffer(encryptedData);
    const decryptedPrivateKeyBuffer: ArrayBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv } as AesGcmParams,
      derivedKey,
      encryptedDataBuffer
    );

    // Private Key importieren
    const privateKey: CryptoKey = await crypto.subtle.importKey(
      "pkcs8",
      decryptedPrivateKeyBuffer,
      {
        name: "X25519",
        namedCurve: "X25519" as const
      },
      true,
      ["deriveKey", "deriveBits"]
    );

    return privateKey;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown decryption error';
    const decryptionError: DecryptionError = new Error(
      `Decryption failed: ${errorMessage}`
    ) as DecryptionError;
    decryptionError.code = 'DECRYPTION_FAILED';
    throw decryptionError;
  }
}

// 3. Kompletter Workflow: Key Pair erstellen + Private Key verschlüsseln
async function createAndEncryptKeyPair(
  password: string
): Promise<EncryptedKeyPair> {
  try {
    // X25519 Key Pair generieren
    const keyPair: CryptoKeyPair = await crypto.subtle.generateKey(
      {
        name: "X25519",
        namedCurve: "X25519" as const
      },
      true,
      ["deriveKey", "deriveBits"]
    );

    // Public Key exportieren (unverschl�sselt)
    const publicKeyBuffer: ArrayBuffer = await crypto.subtle.exportKey("raw", keyPair.publicKey);
    const publicKeyBase64: string = btoa(String.fromCharCode(...new Uint8Array(publicKeyBuffer)));

    // Private Key mit Passwort verschl�sseln
    const encryptedPrivateKey: string = await encryptPrivateKeyWithPassword(keyPair.privateKey, password);

    return {
      publicKey: publicKeyBase64,        // F�r andere User sichtbar
      encryptedPrivateKey: encryptedPrivateKey  // Verschl�sselt auf Server speichern
    };
  } catch (error) {
    throw new Error(`Key pair creation failed: ${(error as Error).message}`);
  }
}

async function decryptAndGetKeyPair(
  encryptedKeyPair: EncryptedKeyPair,
  password: string
): Promise<CryptoKeyPair> {
  try {
    const privateKey: CryptoKey = await decryptPrivateKeyWithPassword(
      encryptedKeyPair.encryptedPrivateKey,
      password
    );
    console.log("Private Key imported successfully");

    // Public Key Base64 validieren
    if (!isValidBase64(encryptedKeyPair.publicKey)) {
      throw new Error("Ung�ltiger Public Key Base64-String");
    }

    // Public Key Buffer konvertieren und validieren
    const publicKeyBuffer: ArrayBuffer = base64ToArrayBuffer(encryptedKeyPair.publicKey);
    const publicKeyBytes = new Uint8Array(publicKeyBuffer);

    if (publicKeyBytes.length !== 32) {
      throw new Error(`Public Key muss genau 32 Bytes lang sein, ist aber ${publicKeyBytes.length} Bytes`);
    }

    console.log("Public Key Buffer Length:", publicKeyBytes.length);
    console.log("Public Key Buffer (hex):", Array.from(publicKeyBytes).map(b => b.toString(16).padStart(2, '0')).join(' '));

    // Public Key importieren
    const publicKey: CryptoKey = await crypto.subtle.importKey(
      "raw",  // F�r X25519 immer "raw"
      publicKeyBuffer,
      {
        name: "ECDH",  // Verwende "ECDH" statt "X25519" \u2013 das ist der korrekte Algorithmus-Name f�r X25519 in Web Crypto
        namedCurve: "X25519" as const
      },
      true,
      ["deriveBits", "deriveKey"]  // Erweitere um "deriveKey" falls ben�tigt
    );

    console.log("Public Key imported successfully");

    return { publicKey, privateKey };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    console.error("Fehler in decryptAndGetKeyPair:", errorMessage);
    throw new Error(`Key Pair Dekodierung fehlgeschlagen: ${errorMessage}`);
  }
}

// Verbesserte Base64-Funktion mit besserer Fehlerbehandlung
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  try {
    // Base64 decodieren (atob erwartet standard Base64)
    const binaryString = atob(base64.replace(/[^A-Za-z0-9+/=]/g, ''));  // Entferne ung�ltige Zeichen
    const len = binaryString.length;
    const bytes = new Uint8Array(len);

    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }

    if (bytes.length === 0) {
      throw new Error("Dekodierter Buffer ist leer");
    }

    return bytes.buffer;
  } catch (error) {
    throw new Error(`Base64-Dekodierung fehlgeschlagen: ${(error as Error).message}`);
  }
}

// Type Guards für bessere Type Safety
function isValidBase64(str: string): boolean {
  try {
    atob(str);
    return true;
  } catch {
    return false;
  }
}

function isValidPassword(password: string): boolean {
  return password.length >= 8 && password.length <= 128;
}

function uint8ArrayToArrayBuffer(uint8Array: Uint8Array): ArrayBuffer {
  return uint8Array.buffer.slice(
    uint8Array.byteOffset,
    uint8Array.byteOffset + uint8Array.byteLength
  ) as ArrayBuffer;
}

// Export Types für andere Module
export type {
  EncryptedKeyPair,
  DecryptionError
};

export {
  encryptPrivateKeyWithPassword,
  decryptPrivateKeyWithPassword,
  createAndEncryptKeyPair,
  decryptAndGetKeyPair,
  isValidBase64,
  isValidPassword
};

async function key_test(encryptedKeyPair: EncryptedKeyPair, password: string) {

  // const encrypted = await crypto.subtle.encrypt(
  //   { name: "RSA-OAEP" },
  //   publicKey,
  //   originalMessage
  // );
  // console.log("Verschlüsselt:", encrypted); // Binärer Blob
  // // 3. Entschl�ssle mit Private Key
  // const decrypted = await crypto.subtle.decrypt(
  //   { name: "RSA-OAEP" },
  //   privateKey,
  //   encrypted
  // );
  // const decryptedMessage = new TextDecoder().decode(decrypted);
  //console.log("Entschlüsselt:", decryptedMessage); // "Hallo, das ist ein geheimer
}
async function testDirectImport() {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "X25519" },  // Verwende ECDH!
    true,
    ["deriveBits"]
  );

  const exported = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  console.log("Direkt exportierter Buffer Length:", exported.byteLength);
  console.log("Direkt hex:", Array.from(new Uint8Array(exported)).map(b => b.toString(16).padStart(2, '0')).join(' '));

  // Sofort importieren
  const imported = await crypto.subtle.importKey(
    "raw",
    exported,
    { name: "ECDH", namedCurve: "X25519" },
    true,
    ["deriveBits"]
  );
  console.log("Direkter Import erfolgreich!");
}
testDirectImport();