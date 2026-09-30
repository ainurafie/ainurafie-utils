/**
 * NVX request signature.
 *
 * Canonical (digabung TANPA separator):
 *   METHOD + REQUEST URI + X-Request-Id + X-App-Id + X-Platform + X-Timestamp + BODY TOKEN
 *
 * Signature = HMAC-SHA256(canonical, secret) dalam hex.
 * Sama dengan RequiredSignaturePublicHeaders default nvx-go-middleware (sejak 28/09/2026).
 *
 * Aturan body token (ResolveBodyToken di nvx-go-middleware):
 *   multipart/*   -> "UNSIGNED"
 *   body kosong   -> "EMPTY"
 *   lainnya       -> SHA256(byte body) dalam hex, termasuk binary
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
  /** App id dari gateway shield, dikirim sebagai header `X-App-Id` dan masuk canonical. */
  appId?: string;
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
  appId: string;
  platform: string;
  timestamp: string;
  requestURI: string;
  contentType: string;
  /**
   * Body yang harus dikirim. JSON/object/URLSearchParams menjadi string persis seperti yang di-hash;
   * FormData dan binary dikembalikan apa adanya.
   */
  body: string | FormData | Blob | ArrayBuffer | ArrayBufferView;
  bodyToken: string;
  canonical: string;
  /** Header siap pakai untuk request. */
  headers: Record<string, string>;
}

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
  if (typeof Blob !== "undefined" && body instanceof Blob && body.type) return body.type;
  if (isBinaryBody(body)) return "application/octet-stream";
  return "application/json";
}

function isMultipart(contentType: string): boolean {
  return contentType.trim().toLowerCase().startsWith("multipart/");
}

/** Body yang dikirim. Selain FormData dan binary, body diubah menjadi string. */
function serializeBody(body: SignatureBody): SignatureResult["body"] {
  if (body === null || body === undefined) return "";
  if (typeof body === "string") return body;
  if (body instanceof URLSearchParams) return body.toString();
  if (typeof FormData !== "undefined" && body instanceof FormData) return body;
  if (isBinaryBody(body)) return body;
  return JSON.stringify(body);
}

/** Byte body yang di-hash server. FormData tidak perlu (selalu "UNSIGNED"). */
async function bodyBytes(body: SignatureResult["body"]): Promise<Uint8Array<ArrayBuffer>> {
  if (typeof body === "string") return new TextEncoder().encode(body);
  if (typeof Blob !== "undefined" && body instanceof Blob) return new Uint8Array(await body.arrayBuffer());
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength).slice();
  return new Uint8Array();
}

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(data: Uint8Array<ArrayBuffer>): Promise<string> {
  const crypto = await getCrypto();
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

async function resolveBodyToken(contentType: string, body: SignatureResult["body"]): Promise<string> {
  if (isMultipart(contentType)) return "UNSIGNED";
  const bytes = await bodyBytes(body);
  if (bytes.length === 0) return "EMPTY";
  return sha256Hex(bytes);
}

/**
 * Generate NVX request signature beserta header-nya.
 *
 * @example
 * const { headers, body } = await generateSignature({
 *   secret: PUBLIC_KEY_SIGNATURE,
 *   appId: APP_ID,
 *   gatewayKey: X_DEV_GATEWAY_KEY,
 *   method: "POST",
 *   url: "/api/users",
 *   body: { name: "Budi" },
 * });
 * await fetch(BASE_URL + "/api/users", {
 *   method: "POST",
 *   headers, // sudah termasuk Content-Type
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
  const appId = options.appId ?? "";
  const timestamp = String(options.timestamp ?? Math.floor(Date.now() / 1000));
  const requestURI = getRequestURI(options.url, options.pathPrefix);
  const contentType = options.contentType || inferContentType(options.body);
  const body = serializeBody(options.body);
  const bodyToken = await resolveBodyToken(contentType, body);

  const canonical = [method, requestURI, requestId, appId, platform, timestamp, bodyToken].join("");
  const signature = await hmacSha256Hex(options.secret, canonical);

  const headers: Record<string, string> = {
    "X-Request-Id": requestId,
    "X-Platform": platform,
    "X-Timestamp": timestamp,
    "X-Signature": signature,
  };
  // Server menghitung body token dari header Content-Type, jadi kirim nilai yang sama.
  // Multipart dilewati: boundary-nya diisi otomatis oleh fetch/browser.
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
    headers,
  };
}
