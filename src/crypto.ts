/**
 * Utility ECC (NIST P-256), port dari versi Go dan kompatibel dengannya:
 *
 * - Signature: ECDSA + SHA-256, format ASN.1 DER (sama seperti `ecdsa.SignASN1`).
 * - Enkripsi (ECIES): ECDH ephemeral + SHA-256(shared secret) sebagai key AES-256-GCM.
 *   Format: [ephemeral public key 65 byte] + [nonce 12 byte] + [ciphertext + tag 16 byte]
 * - Key PEM: public key SPKI (`PUBLIC KEY`), private key PKCS#8 (`PRIVATE KEY`).
 *
 * Key berupa `CryptoKey` ECDSA yang extractable, karena untuk enkripsi key perlu
 * diekspor lalu diimpor ulang sebagai ECDH (Web Crypto memisahkan ECDSA dan ECDH).
 */

import { getCrypto } from "./internal/webcrypto";

/** Data input: string (di-encode UTF-8) atau bytes. */
export type ECCData = string | Uint8Array;

const CURVE = "P-256";
const COORD_LENGTH = 32;
const PUBLIC_KEY_LENGTH = 65;
const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;

function toBytes(data: ECCData): Uint8Array<ArrayBuffer> {
  return typeof data === "string" ? new TextEncoder().encode(data) : new Uint8Array(data);
}

/** Encode bytes ke base64. */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/** Decode base64 ke bytes. */
export function base64ToBytes(base64: string): Uint8Array<ArrayBuffer> {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/* ------------------------------------------------------------
 * ASN.1 DER <-> raw (r || s)
 * Web Crypto memakai format raw, Go memakai DER.
 * ------------------------------------------------------------ */

function encodeDerInteger(value: Uint8Array): number[] {
  let i = 0;
  while (i < value.length - 1 && value[i] === 0) i++;
  const bytes = Array.from(value.subarray(i));
  if (bytes[0] & 0x80) bytes.unshift(0);
  return [0x02, bytes.length, ...bytes];
}

function rawToDer(raw: Uint8Array): Uint8Array<ArrayBuffer> {
  const r = encodeDerInteger(raw.subarray(0, COORD_LENGTH));
  const s = encodeDerInteger(raw.subarray(COORD_LENGTH));
  return new Uint8Array([0x30, r.length + s.length, ...r, ...s]);
}

function derToRaw(der: Uint8Array): Uint8Array<ArrayBuffer> | null {
  let pos = 0;
  if (der[pos++] !== 0x30) return null;
  let length = der[pos++];
  if (length === 0x81) length = der[pos++];
  if (pos + length !== der.length) return null;

  const raw = new Uint8Array(COORD_LENGTH * 2);
  for (const offset of [0, COORD_LENGTH]) {
    if (der[pos++] !== 0x02) return null;
    const n = der[pos++];
    if (!(n > 0 && pos + n <= der.length)) return null;
    let value = der.subarray(pos, pos + n);
    pos += n;
    while (value.length > 0 && value[0] === 0) value = value.subarray(1);
    if (value.length > COORD_LENGTH) return null;
    raw.set(value, offset + COORD_LENGTH - value.length);
  }
  return pos === der.length ? raw : null;
}

/* ------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------ */

/** Ubah key ECDSA menjadi key ECDH (via export/import). Key ECDH dikembalikan apa adanya. */
async function toECDHKey(crypto: Crypto, key: CryptoKey): Promise<CryptoKey> {
  if (key.algorithm.name === "ECDH") return key;
  const algorithm = { name: "ECDH", namedCurve: CURVE };
  if (key.type === "public") {
    const spki = await crypto.subtle.exportKey("spki", key);
    return crypto.subtle.importKey("spki", spki, algorithm, false, []);
  }
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", key);
  return crypto.subtle.importKey("pkcs8", pkcs8, algorithm, false, ["deriveBits"]);
}

/** AES-256-GCM key = SHA-256(shared secret ECDH). */
async function deriveAESKey(
  crypto: Crypto,
  privateKey: CryptoKey,
  publicKey: CryptoKey,
  usage: "encrypt" | "decrypt",
): Promise<CryptoKey> {
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256);
  const hash = await crypto.subtle.digest("SHA-256", shared);
  return crypto.subtle.importKey("raw", hash, { name: "AES-GCM" }, false, [usage]);
}

function toPEM(label: string, der: ArrayBuffer): string {
  const lines = bytesToBase64(new Uint8Array(der)).match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

function fromPEM(label: string, pem: string): Uint8Array<ArrayBuffer> {
  const match = pem.match(new RegExp(`-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`));
  if (!match) throw new Error(`PEM ${label} tidak ditemukan`);
  return base64ToBytes(match[1].replace(/\s+/g, ""));
}

/* ------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------ */

/** Generate key pair ECDSA P-256 baru (extractable). */
export async function generateECCKeyPair(): Promise<CryptoKeyPair> {
  const crypto = await getCrypto();
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: CURVE }, true, ["sign", "verify"]);
}

/** Tandatangani `data` (SHA-256 + ECDSA). Hasil berupa signature ASN.1 DER. */
export async function signECC(privateKey: CryptoKey, data: ECCData): Promise<Uint8Array> {
  if (!privateKey) throw new Error("signECC: private key wajib diisi");
  const crypto = await getCrypto();
  const raw = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    toBytes(data),
  );
  return rawToDer(new Uint8Array(raw));
}

/** Verifikasi signature ASN.1 DER dari `data`. */
export async function verifyECC(
  publicKey: CryptoKey,
  data: ECCData,
  signature: Uint8Array,
): Promise<boolean> {
  if (!publicKey) return false;
  const raw = derToRaw(signature);
  if (!raw) return false;
  try {
    const crypto = await getCrypto();
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, raw, toBytes(data));
  } catch {
    return false;
  }
}

/** Enkripsi `data` untuk pemilik `recipientPublicKey` (ECIES, AES-256-GCM). */
export async function encryptECC(recipientPublicKey: CryptoKey, data: ECCData): Promise<Uint8Array> {
  if (!recipientPublicKey) throw new Error("encryptECC: recipient public key wajib diisi");
  const crypto = await getCrypto();

  const recipient = await toECDHKey(crypto, recipientPublicKey);
  const ephemeral = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: CURVE }, true, [
    "deriveBits",
  ]);
  const aesKey = await deriveAESKey(crypto, ephemeral.privateKey, recipient, "encrypt");

  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, toBytes(data));
  const ephemeralPub = await crypto.subtle.exportKey("raw", ephemeral.publicKey);

  const result = new Uint8Array(PUBLIC_KEY_LENGTH + NONCE_LENGTH + ciphertext.byteLength);
  result.set(new Uint8Array(ephemeralPub), 0);
  result.set(nonce, PUBLIC_KEY_LENGTH);
  result.set(new Uint8Array(ciphertext), PUBLIC_KEY_LENGTH + NONCE_LENGTH);
  return result;
}

/** Dekripsi data hasil `encryptECC`. */
export async function decryptECC(privateKey: CryptoKey, packedData: Uint8Array): Promise<Uint8Array> {
  if (!privateKey) throw new Error("decryptECC: private key wajib diisi");
  if (packedData.length < PUBLIC_KEY_LENGTH + NONCE_LENGTH + TAG_LENGTH) {
    throw new Error("decryptECC: ciphertext terlalu pendek atau rusak");
  }
  const crypto = await getCrypto();
  const ecdhPrivate = await toECDHKey(crypto, privateKey);

  const pubBytes = packedData.slice(0, PUBLIC_KEY_LENGTH);
  const nonce = packedData.slice(PUBLIC_KEY_LENGTH, PUBLIC_KEY_LENGTH + NONCE_LENGTH);
  const ciphertext = packedData.slice(PUBLIC_KEY_LENGTH + NONCE_LENGTH);

  let ephemeralPub: CryptoKey;
  try {
    ephemeralPub = await crypto.subtle.importKey("raw", pubBytes, { name: "ECDH", namedCurve: CURVE }, false, []);
  } catch {
    throw new Error("decryptECC: ephemeral public key di ciphertext tidak valid");
  }

  const aesKey = await deriveAESKey(crypto, ecdhPrivate, ephemeralPub, "decrypt");
  try {
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, aesKey, ciphertext);
    return new Uint8Array(plaintext);
  } catch {
    throw new Error("decryptECC: dekripsi gagal (key salah atau data diubah)");
  }
}

/** Export public key ke PEM (SPKI). Aman dikirim ke frontend. */
export async function exportPublicKeyAsPEM(publicKey: CryptoKey): Promise<string> {
  const crypto = await getCrypto();
  return toPEM("PUBLIC KEY", await crypto.subtle.exportKey("spki", publicKey));
}

/** Export private key ke PEM (PKCS#8). Simpan dengan aman, jangan dikirim ke frontend! */
export async function exportPrivateKeyAsPEM(privateKey: CryptoKey): Promise<string> {
  const crypto = await getCrypto();
  return toPEM("PRIVATE KEY", await crypto.subtle.exportKey("pkcs8", privateKey));
}

/** Parse PEM (SPKI) menjadi public key ECDSA P-256. */
export async function parsePublicKeyFromPEM(pem: string): Promise<CryptoKey> {
  const crypto = await getCrypto();
  try {
    return await crypto.subtle.importKey("spki", fromPEM("PUBLIC KEY", pem), { name: "ECDSA", namedCurve: CURVE }, true, [
      "verify",
    ]);
  } catch {
    throw new Error("parsePublicKeyFromPEM: bukan public key ECDSA P-256");
  }
}

/** Parse PEM (PKCS#8) menjadi private key ECDSA P-256. */
export async function parsePrivateKeyFromPEM(pem: string): Promise<CryptoKey> {
  const crypto = await getCrypto();
  try {
    return await crypto.subtle.importKey("pkcs8", fromPEM("PRIVATE KEY", pem), { name: "ECDSA", namedCurve: CURVE }, true, [
      "sign",
    ]);
  } catch {
    throw new Error("parsePrivateKeyFromPEM: bukan private key ECDSA P-256");
  }
}
