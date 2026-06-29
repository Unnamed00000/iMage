const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export const PBKDF2_ITERATIONS = 600_000;
export const SECRET_MARKER = hexToBytes("9f3a7cc2e84d11b6a501d8734ef092bd");
const LEGACY_MARKER = encoder.encode("---SECRET_JSON_START_V1---");

export function concatBytes(...parts) {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

export function hexToBytes(hex) {
  if (hex.length % 2) throw new Error("Invalid hex value");
  const result = new Uint8Array(hex.length / 2);
  for (let i = 0; i < result.length; i += 1) {
    result[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return result;
}

export function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

export function base64ToBytes(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function randomBytes(length) {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

export async function deriveKeyBytes(
  password,
  salt,
  iterations = PBKDF2_ITERATIONS,
) {
  if (!password) throw new Error("Введите пароль");
  const material = await globalThis.crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await globalThis.crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    material,
    256,
  );
  return new Uint8Array(bits);
}

async function importHmacKey(keyBytes, usages) {
  return globalThis.crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    usages,
  );
}

export async function fernetEncryptRaw(keyBytes, plainBytes) {
  if (keyBytes.length !== 32) throw new Error("Invalid Fernet key");
  const signingKey = keyBytes.slice(0, 16);
  const encryptionKey = keyBytes.slice(16, 32);
  const iv = randomBytes(16);
  const header = new Uint8Array(25);
  header[0] = 0x80;
  new DataView(header.buffer).setBigUint64(
    1,
    BigInt(Math.floor(Date.now() / 1000)),
    false,
  );
  header.set(iv, 9);

  const aesKey = await globalThis.crypto.subtle.importKey(
    "raw",
    encryptionKey,
    "AES-CBC",
    false,
    ["encrypt"],
  );
  const ciphertext = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: "AES-CBC", iv },
      aesKey,
      plainBytes,
    ),
  );
  const signedData = concatBytes(header, ciphertext);
  const hmacKey = await importHmacKey(signingKey, ["sign"]);
  const signature = new Uint8Array(
    await globalThis.crypto.subtle.sign("HMAC", hmacKey, signedData),
  );
  return concatBytes(signedData, signature);
}

export async function fernetDecryptRaw(keyBytes, token) {
  if (keyBytes.length !== 32 || token.length < 73 || token[0] !== 0x80) {
    throw new Error("Invalid Fernet token");
  }
  const signingKey = keyBytes.slice(0, 16);
  const encryptionKey = keyBytes.slice(16, 32);
  const signedData = token.slice(0, -32);
  const signature = token.slice(-32);
  const hmacKey = await importHmacKey(signingKey, ["verify"]);
  const verified = await globalThis.crypto.subtle.verify(
    "HMAC",
    hmacKey,
    signature,
    signedData,
  );
  if (!verified) throw new Error("Invalid Fernet signature");

  const iv = token.slice(9, 25);
  const ciphertext = token.slice(25, -32);
  const aesKey = await globalThis.crypto.subtle.importKey(
    "raw",
    encryptionKey,
    "AES-CBC",
    false,
    ["decrypt"],
  );
  return new Uint8Array(
    await globalThis.crypto.subtle.decrypt(
      { name: "AES-CBC", iv },
      aesKey,
      ciphertext,
    ),
  );
}

function findLastBytes(haystack, needle) {
  for (let start = haystack.length - needle.length; start >= 0; start -= 1) {
    let matches = true;
    for (let index = 0; index < needle.length; index += 1) {
      if (haystack[start + index] !== needle[index]) {
        matches = false;
        break;
      }
    }
    if (matches) return start;
  }
  return -1;
}

export function plainTextToJson(text) {
  if (!text.trim()) throw new Error("Введите секретный текст");
  return JSON.stringify({ _format: "secret_text_v1", text }, null, 2);
}

export function jsonToPlainText(jsonText) {
  const parsed = JSON.parse(jsonText);
  if (
    parsed &&
    typeof parsed === "object" &&
    parsed._format === "secret_text_v1" &&
    typeof parsed.text === "string"
  ) {
    return parsed.text;
  }
  if (
    parsed &&
    typeof parsed === "object" &&
    Object.keys(parsed).length === 1 &&
    typeof parsed.message === "string"
  ) {
    return parsed.message;
  }
  return JSON.stringify(parsed, null, 2);
}

export async function createSecretPayload(jsonText, password) {
  JSON.parse(jsonText);
  const salt = randomBytes(16);
  const key = await deriveKeyBytes(password, salt);
  const token = await fernetEncryptRaw(key, encoder.encode(jsonText));
  return concatBytes(SECRET_MARKER, salt, token);
}

export function parseSecretPayload(imageBytes) {
  let marker = SECRET_MARKER;
  let position = findLastBytes(imageBytes, marker);
  let legacy = false;
  if (position < 0) {
    marker = LEGACY_MARKER;
    position = findLastBytes(imageBytes, marker);
    legacy = true;
  }
  if (position < 0) throw new Error("Secret not found");

  const payload = imageBytes.slice(position + marker.length);
  if (payload.length <= 16) throw new Error("Damaged payload");
  const salt = payload.slice(0, 16);
  const storedToken = payload.slice(16);
  const token = legacy
    ? base64ToBytes(decoder.decode(storedToken))
    : storedToken;
  return { salt, token };
}

export async function verifySecretPassword(payload, password) {
  try {
    const key = await deriveKeyBytes(password, payload.salt);
    const plainBytes = await fernetDecryptRaw(key, payload.token);
    JSON.parse(decoder.decode(plainBytes));
    return true;
  } catch {
    return false;
  }
}

export async function extractSecretJson(imageBytes, password) {
  const payload = parseSecretPayload(imageBytes);
  const key = await deriveKeyBytes(password, payload.salt);
  const plainBytes = await fernetDecryptRaw(key, payload.token);
  const jsonText = decoder.decode(plainBytes);
  JSON.parse(jsonText);
  return jsonText;
}
