'use strict';

// src/string.ts
function capitalize(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}
function slugify(str) {
  return str.normalize("NFKD").replace(/[̀-ͯ]/g, "").toLowerCase().trim().replace(/[^a-z0-9\s-]/g, "").replace(/[\s-]+/g, "-").replace(/^-|-$/g, "");
}
function truncate(str, length, suffix = "...") {
  return str.length > length ? str.slice(0, length) + suffix : str;
}

// src/number.ts
function formatRupiah(value, withSymbol = true) {
  const formatted = new Intl.NumberFormat("id-ID", {
    maximumFractionDigits: 0
  }).format(value);
  return withSymbol ? `Rp ${formatted}` : formatted;
}
function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}
function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

// src/array.ts
function unique(arr) {
  return [...new Set(arr)];
}
function chunk(arr, size) {
  const result = [];
  for (let i = 0; i < arr.length; i += size) {
    result.push(arr.slice(i, i + size));
  }
  return result;
}
function groupBy(arr, getKey) {
  return arr.reduce(
    (acc, item) => {
      const key = getKey(item);
      (acc[key] || (acc[key] = [])).push(item);
      return acc;
    },
    {}
  );
}

// src/async.ts
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
function debounce(fn, wait) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), wait);
  };
}

// src/internal/webcrypto.ts
async function getCrypto() {
  if (globalThis.crypto?.subtle) return globalThis.crypto;
  const specifier = "node:crypto";
  const mod = await import(
    /* @vite-ignore */
    /* webpackIgnore: true */
    specifier
  );
  return mod.webcrypto;
}

// src/signature.ts
function normalizePathPrefix(prefix) {
  let p = (prefix ?? "").trim();
  if (!p || p === "/") return "";
  if (!p.startsWith("/")) p = "/" + p;
  while (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
  return p;
}
function getRequestURI(url, pathPrefix) {
  const parsed = new URL(url, "http://localhost");
  let uri = (parsed.pathname || "/") + parsed.search;
  const prefix = normalizePathPrefix(pathPrefix);
  if (prefix) uri = uri === "/" ? prefix + "/" : prefix + uri;
  return uri;
}
function isBinaryBody(body) {
  return typeof Blob !== "undefined" && body instanceof Blob || body instanceof ArrayBuffer || ArrayBuffer.isView(body);
}
function inferContentType(body) {
  if (body === null || body === void 0 || typeof body === "string") return "";
  if (typeof FormData !== "undefined" && body instanceof FormData) return "multipart/form-data";
  if (body instanceof URLSearchParams) return "application/x-www-form-urlencoded";
  if (typeof Blob !== "undefined" && body instanceof Blob && body.type) return body.type;
  if (isBinaryBody(body)) return "application/octet-stream";
  return "application/json";
}
function isMultipart(contentType) {
  return contentType.trim().toLowerCase().startsWith("multipart/");
}
function serializeBody(body) {
  if (body === null || body === void 0) return "";
  if (typeof body === "string") return body;
  if (body instanceof URLSearchParams) return body.toString();
  if (typeof FormData !== "undefined" && body instanceof FormData) return body;
  if (isBinaryBody(body)) return body;
  return JSON.stringify(body);
}
async function bodyBytes(body) {
  if (typeof body === "string") return new TextEncoder().encode(body);
  if (typeof Blob !== "undefined" && body instanceof Blob) return new Uint8Array(await body.arrayBuffer());
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength).slice();
  return new Uint8Array();
}
function toHex(buffer) {
  return Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, "0")).join("");
}
async function sha256Hex(data) {
  const crypto = await getCrypto();
  return toHex(await crypto.subtle.digest("SHA-256", data));
}
async function hmacSha256Hex(secret, message) {
  const crypto = await getCrypto();
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return toHex(await crypto.subtle.sign("HMAC", key, encoder.encode(message)));
}
async function resolveBodyToken(contentType, body) {
  if (isMultipart(contentType)) return "UNSIGNED";
  const bytes = await bodyBytes(body);
  if (bytes.length === 0) return "EMPTY";
  return sha256Hex(bytes);
}
async function generateSignature(options) {
  if (!options.secret) throw new Error("generateSignature: `secret` wajib diisi");
  const method = (options.method || "GET").toUpperCase();
  const platform = options.platform || "web";
  const requestId = options.requestId || (await getCrypto()).randomUUID();
  const appId = options.appId ?? "";
  const timestamp = String(options.timestamp ?? Math.floor(Date.now() / 1e3));
  const requestURI = getRequestURI(options.url, options.pathPrefix);
  const contentType = options.contentType || inferContentType(options.body);
  const body = serializeBody(options.body);
  const bodyToken = await resolveBodyToken(contentType, body);
  const canonical = [method, requestURI, requestId, appId, platform, timestamp, bodyToken].join("");
  const signature = await hmacSha256Hex(options.secret, canonical);
  const headers = {
    "X-Request-Id": requestId,
    "X-Platform": platform,
    "X-Timestamp": timestamp,
    "X-Signature": signature
  };
  if (contentType && !isMultipart(contentType)) headers["Content-Type"] = contentType;
  if (appId) headers["X-App-Id"] = appId;
  if (options.gatewayKey) headers["X-Dev-Gateway-Key"] = options.gatewayKey;
  return {
    signature,
    method,
    requestId,
    appId,
    platform,
    timestamp,
    requestURI,
    contentType,
    body,
    bodyToken,
    canonical,
    headers
  };
}

// src/crypto.ts
var CURVE = "P-256";
var COORD_LENGTH = 32;
var PUBLIC_KEY_LENGTH = 65;
var NONCE_LENGTH = 12;
var TAG_LENGTH = 16;
function toBytes(data) {
  return typeof data === "string" ? new TextEncoder().encode(data) : new Uint8Array(data);
}
function bytesToBase64(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}
function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
function encodeDerInteger(value) {
  let i = 0;
  while (i < value.length - 1 && value[i] === 0) i++;
  const bytes = Array.from(value.subarray(i));
  if (bytes[0] & 128) bytes.unshift(0);
  return [2, bytes.length, ...bytes];
}
function rawToDer(raw) {
  const r = encodeDerInteger(raw.subarray(0, COORD_LENGTH));
  const s = encodeDerInteger(raw.subarray(COORD_LENGTH));
  return new Uint8Array([48, r.length + s.length, ...r, ...s]);
}
function derToRaw(der) {
  let pos = 0;
  if (der[pos++] !== 48) return null;
  let length = der[pos++];
  if (length === 129) length = der[pos++];
  if (pos + length !== der.length) return null;
  const raw = new Uint8Array(COORD_LENGTH * 2);
  for (const offset of [0, COORD_LENGTH]) {
    if (der[pos++] !== 2) return null;
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
async function toECDHKey(crypto, key) {
  if (key.algorithm.name === "ECDH") return key;
  const algorithm = { name: "ECDH", namedCurve: CURVE };
  if (key.type === "public") {
    const spki = await crypto.subtle.exportKey("spki", key);
    return crypto.subtle.importKey("spki", spki, algorithm, false, []);
  }
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", key);
  return crypto.subtle.importKey("pkcs8", pkcs8, algorithm, false, ["deriveBits"]);
}
async function deriveAESKey(crypto, privateKey, publicKey, usage) {
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256);
  const hash = await crypto.subtle.digest("SHA-256", shared);
  return crypto.subtle.importKey("raw", hash, { name: "AES-GCM" }, false, [usage]);
}
function toPEM(label, der) {
  const lines = bytesToBase64(new Uint8Array(der)).match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----
${lines.join("\n")}
-----END ${label}-----
`;
}
function fromPEM(label, pem) {
  const match = pem.match(new RegExp(`-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`));
  if (!match) throw new Error(`PEM ${label} tidak ditemukan`);
  return base64ToBytes(match[1].replace(/\s+/g, ""));
}
async function generateECCKeyPair() {
  const crypto = await getCrypto();
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: CURVE }, true, ["sign", "verify"]);
}
async function signECC(privateKey, data) {
  if (!privateKey) throw new Error("signECC: private key wajib diisi");
  const crypto = await getCrypto();
  const raw = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    toBytes(data)
  );
  return rawToDer(new Uint8Array(raw));
}
async function verifyECC(publicKey, data, signature) {
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
async function encryptECC(recipientPublicKey, data) {
  if (!recipientPublicKey) throw new Error("encryptECC: recipient public key wajib diisi");
  const crypto = await getCrypto();
  const recipient = await toECDHKey(crypto, recipientPublicKey);
  const ephemeral = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: CURVE }, true, [
    "deriveBits"
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
async function decryptECC(privateKey, packedData) {
  if (!privateKey) throw new Error("decryptECC: private key wajib diisi");
  if (packedData.length < PUBLIC_KEY_LENGTH + NONCE_LENGTH + TAG_LENGTH) {
    throw new Error("decryptECC: ciphertext terlalu pendek atau rusak");
  }
  const crypto = await getCrypto();
  const ecdhPrivate = await toECDHKey(crypto, privateKey);
  const pubBytes = packedData.slice(0, PUBLIC_KEY_LENGTH);
  const nonce = packedData.slice(PUBLIC_KEY_LENGTH, PUBLIC_KEY_LENGTH + NONCE_LENGTH);
  const ciphertext = packedData.slice(PUBLIC_KEY_LENGTH + NONCE_LENGTH);
  let ephemeralPub;
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
async function exportPublicKeyAsPEM(publicKey) {
  const crypto = await getCrypto();
  return toPEM("PUBLIC KEY", await crypto.subtle.exportKey("spki", publicKey));
}
async function exportPrivateKeyAsPEM(privateKey) {
  const crypto = await getCrypto();
  return toPEM("PRIVATE KEY", await crypto.subtle.exportKey("pkcs8", privateKey));
}
async function parsePublicKeyFromPEM(pem) {
  const crypto = await getCrypto();
  try {
    return await crypto.subtle.importKey("spki", fromPEM("PUBLIC KEY", pem), { name: "ECDSA", namedCurve: CURVE }, true, [
      "verify"
    ]);
  } catch {
    throw new Error("parsePublicKeyFromPEM: bukan public key ECDSA P-256");
  }
}
async function parsePrivateKeyFromPEM(pem) {
  const crypto = await getCrypto();
  try {
    return await crypto.subtle.importKey("pkcs8", fromPEM("PRIVATE KEY", pem), { name: "ECDSA", namedCurve: CURVE }, true, [
      "sign"
    ]);
  } catch {
    throw new Error("parsePrivateKeyFromPEM: bukan private key ECDSA P-256");
  }
}

exports.base64ToBytes = base64ToBytes;
exports.bytesToBase64 = bytesToBase64;
exports.capitalize = capitalize;
exports.chunk = chunk;
exports.clamp = clamp;
exports.debounce = debounce;
exports.decryptECC = decryptECC;
exports.encryptECC = encryptECC;
exports.exportPrivateKeyAsPEM = exportPrivateKeyAsPEM;
exports.exportPublicKeyAsPEM = exportPublicKeyAsPEM;
exports.formatRupiah = formatRupiah;
exports.generateECCKeyPair = generateECCKeyPair;
exports.generateSignature = generateSignature;
exports.groupBy = groupBy;
exports.parsePrivateKeyFromPEM = parsePrivateKeyFromPEM;
exports.parsePublicKeyFromPEM = parsePublicKeyFromPEM;
exports.randomInt = randomInt;
exports.signECC = signECC;
exports.sleep = sleep;
exports.slugify = slugify;
exports.truncate = truncate;
exports.unique = unique;
exports.verifyECC = verifyECC;
//# sourceMappingURL=index.cjs.map
//# sourceMappingURL=index.cjs.map