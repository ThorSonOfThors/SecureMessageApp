// utils/crypto.ts
// AES-256-GCM password encryption using Web Crypto API
// FINAL STABLE VERSION (Nuxt 3 + TypeScript safe)

const encoder = new TextEncoder()
const decoder = new TextDecoder()

/* =======================================================
   SECURITY CONFIG
======================================================= */

const ITERATIONS = 250_000
const KEY_LENGTH = 256
const SALT_LENGTH = 16
const IV_LENGTH = 12 // AES-GCM standard

/* =======================================================
   ENVIRONMENT SAFETY
======================================================= */

function ensureClient() {
  if (import.meta.server) {
    throw new Error(
      "Crypto operations must run on client side."
    )
  }

  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto API unavailable.")
  }
}

/* =======================================================
   PAYLOAD HELPER
======================================================= */
function parsePayload(input: string) {
  let parsed: any

  try {
    parsed = JSON.parse(input)
  } catch {
    throw new Error("Invalid encrypted message format.")
  }

  if (
    typeof parsed !== "object" ||
    typeof parsed.salt !== "string" ||
    typeof parsed.iv !== "string" ||
    typeof parsed.data !== "string"
  ) {
    throw new Error("Malformed encrypted payload.")
  }

  return parsed
}


/* =======================================================
   SAFE BYTE HELPERS
======================================================= */

// Always produce Uint8Array backed by REAL ArrayBuffer
function cloneBytes(data: Uint8Array): Uint8Array {
  const buffer = new ArrayBuffer(data.byteLength)
  const copy = new Uint8Array(buffer)
  copy.set(data)
  return copy
}

function toRealArrayBuffer(view: Uint8Array): ArrayBuffer {
  // Allocate brand new ArrayBuffer (guaranteed type)
  const buffer = new ArrayBuffer(view.byteLength)
  new Uint8Array(buffer).set(view)
  return buffer
}



// Guaranteed BufferSource acceptable to WebCrypto
function asBufferSource(data: Uint8Array): BufferSource {
  // create guaranteed ArrayBuffer-backed view
  const buffer = new ArrayBuffer(data.byteLength)
  new Uint8Array(buffer).set(data)
  return new Uint8Array(buffer)
}


/* =======================================================
   RANDOM BYTES
======================================================= */

function randomBytes(length: number): Uint8Array {
  const arr = new Uint8Array(length)
  crypto.getRandomValues(arr)
  return arr
}

/* =======================================================
   BASE64 (BINARY SAFE)
======================================================= */

export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)

  let binary = ""
  const chunkSize = 0x8000

  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(
      ...bytes.subarray(i, i + chunkSize)
    )
  }

  return btoa(binary)
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64)
  const len = binary.length
  const bytes = new Uint8Array(len)

  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i)
  }

  return bytes.buffer.slice(0)
}

/* =======================================================
   PASSWORD → AES KEY (PBKDF2)
======================================================= */

async function deriveKey(
  password: string,
  salt: Uint8Array
): Promise<CryptoKey> {

  const passwordKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  )

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: asBufferSource(salt),
      iterations: ITERATIONS,
      hash: "SHA-256"
    },
    passwordKey,
    {
      name: "AES-GCM",
      length: KEY_LENGTH
    },
    false,
    ["encrypt", "decrypt"]
  )
}

/* =======================================================
   ENCRYPT
======================================================= */

export async function encryptMessage(
  message: string,
  password: string
): Promise<string> {

  ensureClient()

  const salt = randomBytes(SALT_LENGTH)
  const iv = randomBytes(IV_LENGTH)

  const key = await deriveKey(password, salt)

  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: asBufferSource(iv)
    },
    key,
    encoder.encode(message)
  )

const payload = {
  v: 1,

  salt: arrayBufferToBase64(
    toRealArrayBuffer(salt)
  ),

  iv: arrayBufferToBase64(
    toRealArrayBuffer(iv)
  ),

  data: arrayBufferToBase64(
  toRealArrayBuffer(new Uint8Array(encrypted))
  )

}



  return JSON.stringify(payload)
}

/* =======================================================
   DECRYPT
======================================================= */

export async function decryptMessage(
  encryptedPayload: string,
  password: string
): Promise<string> {

  ensureClient()

  const payload = parsePayload(encryptedPayload)


  if (!payload?.salt || !payload?.iv || !payload?.data) {
    throw new Error("Invalid encrypted payload.")
  }

  const salt = new Uint8Array(
    base64ToArrayBuffer(payload.salt)
  )

  const iv = new Uint8Array(
    base64ToArrayBuffer(payload.iv)
  )

  const data = base64ToArrayBuffer(payload.data)

  const key = await deriveKey(password, salt)

  let decrypted: ArrayBuffer

  try {
    decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: asBufferSource(iv)
      },
      key,
      data
    )
  } catch {
    // AES-GCM authentication failure
    throw new Error("Wrong password or corrupted message.")
  }

  return decoder.decode(decrypted)
}
