/**
 * NVX request signature.
 *
 * Canonical (digabung TANPA separator):
 *   METHOD + REQUEST URI + X-Request-Id + X-Platform + X-Timestamp + BODY TOKEN
 *
 * Signature = HMAC-SHA256(canonical, secret) dalam hex.
 *
 * Aturan body token:
 *   multipart/*                        -> "UNSIGNED"
 *   binary                             -> "UNSIGNED"
 *   body kosong                        -> "EMPTY"
 *   lainnya (JSON, text, urlencoded)   -> SHA256(body) dalam hex
 *
 * X-Dev-Gateway-Key dikirim sebagai header tapi TIDAK masuk canonical.
 *
 * Memakai Web Crypto, jadi jalan di browser dan Node 18+.
 */

import { getCrypto } from "./internal/webcrypto";

/** Body yang bisa ditandatangani. Object biasa akan di-`JSON.stringify`. */
export type SignatureBody =
  | string
  | URLSearchParams
  | FormData
  | Blob
  | ArrayBuffer
  | ArrayBufferView
  | Record<string, unknown>
  | unknown[]
  | null
  | undefined;

export interface GenerateSignatureOptions {
  /** Secret HMAC (PUBLIC_KEY_SIGNATURE). */
  secret: string;
  /** URL absolut atau relatif, mis. `/api/users?page=1`. */
  url: string;
  /** Default `"GET"`. */
  method?: string;
  body?: SignatureBody;
  /** Content-Type request. Jika kosong, ditebak dari tipe `body`. */
  contentType?: string;
  /** Default `"web"`. */
  platform?: string;
  /** Prefix path yang ditambahkan ke URI saat signing, mis. `/gateway`. */
  pathPrefix?: string;
  /** Jika diisi, ikut dikirim sebagai header `X-Dev-Gateway-Key`. */
  gatewayKey?: string;
  /** Default `crypto.randomUUID()`. */
  requestId?: string;
  /** Unix timestamp dalam detik. Default waktu sekarang. */
  timestamp?: number | string;
}

export interface SignatureResult {
  signature: string;
  method: string;
  requestId: string;
  platform: string;
  timestamp: string;
  requestURI: string;
  contentType: string;
  /** Body persis seperti yang di-hash. Kirim string ini sebagai body request. */
  body: string;
  bodyToken: string;
  canonical: string;
  /** Header siap pakai untuk request. */
  headers: Record<string, string>;
}

const BINARY_TYPES = [
  "application/octet-stream",
  "application/pdf",
  "application/zip",
  "application/gzip",
  "application/x-gzip",
  "application/x-tar",
  "application/wasm",
];

function normalizePathPrefix(prefix: string | undefined): string {
  let p = (prefix ?? "").trim();
  if (!p || p === "/") return "";
  if (!p.startsWith("/")) p = "/" + p;
  while (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
  return p;
}

function getRequestURI(url: string, pathPrefix?: string): string {
  const parsed = new URL(url, "http://localhost");
  let uri = (parsed.pathname || "/") + parsed.search;
  const prefix = normalizePathPrefix(pathPrefix);
  if (prefix) uri = uri === "/" ? prefix + "/" : prefix + uri;
  return uri;
}

function isBinaryBody(body: SignatureBody): body is Blob | ArrayBuffer | ArrayBufferView {
  return (
    (typeof Blob !== "undefined" && body instanceof Blob) ||
    body instanceof ArrayBuffer ||
    ArrayBuffer.isView(body)
  );
}

function inferContentType(body: SignatureBody): string {
  if (body === null || body === undefined || typeof body === "string") return "";
  if (typeof FormData !== "undefined" && body instanceof FormData) return "multipart/form-data";
  if (body instanceof URLSearchParams) return "application/x-www-form-urlencoded";
  if (isBinaryBody(body)) return "application/octet-stream";
  return "application/json";
}

function isMultipart(contentType: string): boolean {
  return contentType.trim().toLowerCase().startsWith("multipart/");
}

function isBinary(contentType: string): boolean {
  const ct = contentType.split(";")[0].trim().toLowerCase();
  if (!ct) return false;
  return (
    BINARY_TYPES.includes(ct) ||
    ct.startsWith("image/") ||
    ct.startsWith("audio/") ||
    ct.startsWith("video/")
  );
}

/** Ubah body menjadi string yang akan di-hash. Multipart/binary -> "". */
function serializeBody(body: SignatureBody): string {
  if (body === null || body === undefined) return "";
  if (typeof body === "string") return body;
  if (body instanceof URLSearchParams) return body.toString();
  if (typeof FormData !== "undefined" && body instanceof FormData) return "";
  if (isBinaryBody(body)) return "";
  return JSON.stringify(body);
}

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(value: string): Promise<string> {
  const crypto = await getCrypto();
  const data = new TextEncoder().encode(value);
  return toHex(await crypto.subtle.digest("SHA-256", data));
}

async function hmacSha256Hex(secret: string, message: string): Promise<string> {
  const crypto = await getCrypto();
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return toHex(await crypto.subtle.sign("HMAC", key, encoder.encode(message)));
}

async function resolveBodyToken(contentType: string, body: string): Promise<string> {
  if (isMultipart(contentType) || isBinary(contentType)) return "UNSIGNED";
  if (body.length === 0) return "EMPTY";
  return sha256Hex(body);
}

/**
 * Generate NVX request signature beserta header-nya.
 *
 * @example
 * const { headers, body } = await generateSignature({
 *   secret: PUBLIC_KEY_SIGNATURE,
 *   gatewayKey: X_DEV_GATEWAY_KEY,
 *   method: "POST",
 *   url: "/api/users",
 *   body: { name: "Budi" },
 * });
 * await fetch(BASE_URL + "/api/users", {
 *   method: "POST",
 *   headers: { "Content-Type": "application/json", ...headers },
 *   body,
 * });
 */
export async function generateSignature(
  options: GenerateSignatureOptions,
): Promise<SignatureResult> {
  if (!options.secret) throw new Error("generateSignature: `secret` wajib diisi");

  const method = (options.method || "GET").toUpperCase();
  const platform = options.platform || "web";
  const requestId = options.requestId || (await getCrypto()).randomUUID();
  const timestamp = String(options.timestamp ?? Math.floor(Date.now() / 1000));
  const requestURI = getRequestURI(options.url, options.pathPrefix);
  const contentType = options.contentType || inferContentType(options.body);
  const body = serializeBody(options.body);
  const bodyToken = await resolveBodyToken(contentType, body);

  const canonical = [method, requestURI, requestId, platform, timestamp, bodyToken].join("");
  const signature = await hmacSha256Hex(options.secret, canonical);

  const headers: Record<string, string> = {
    "X-Request-Id": requestId,
    "X-Platform": platform,
    "X-Timestamp": timestamp,
    "X-Signature": signature,
  };
  if (options.gatewayKey) headers["X-Dev-Gateway-Key"] = options.gatewayKey;

  return {
    signature,
    method,
    requestId,
    platform,
    timestamp,
    requestURI,
    contentType,
    body,
    bodyToken,
    canonical,
    headers,
  };
}
