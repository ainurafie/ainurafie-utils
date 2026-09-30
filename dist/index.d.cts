/** Ubah huruf pertama jadi kapital. */
declare function capitalize(str: string): string;
/** Ubah teks jadi slug URL, contoh: "Halo Dunia!" -> "halo-dunia". */
declare function slugify(str: string): string;
/** Potong teks jika melebihi panjang tertentu. */
declare function truncate(str: string, length: number, suffix?: string): string;

/** Format angka ke Rupiah, contoh: 15000 -> "Rp 15.000". */
declare function formatRupiah(value: number, withSymbol?: boolean): string;
/** Batasi angka di antara min dan max. */
declare function clamp(value: number, min: number, max: number): number;
/** Angka acak bulat antara min dan max (inklusif). */
declare function randomInt(min: number, max: number): number;

/** Hapus duplikat dari array. */
declare function unique<T>(arr: T[]): T[];
/** Pecah array jadi potongan berukuran `size`. */
declare function chunk<T>(arr: T[], size: number): T[][];
/** Kelompokkan item array berdasarkan key. */
declare function groupBy<T, K extends PropertyKey>(arr: T[], getKey: (item: T) => K): Record<K, T[]>;

/** Tunggu selama `ms` milidetik. */
declare function sleep(ms: number): Promise<void>;
/** Tunda eksekusi fungsi sampai tidak dipanggil lagi selama `wait` ms. */
declare function debounce<A extends unknown[]>(fn: (...args: A) => void, wait: number): (...args: A) => void;

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
/** Body yang bisa ditandatangani. Object biasa akan di-`JSON.stringify`. */
type SignatureBody = string | URLSearchParams | FormData | Blob | ArrayBuffer | ArrayBufferView | Record<string, unknown> | unknown[] | null | undefined;
interface GenerateSignatureOptions {
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
interface SignatureResult {
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
declare function generateSignature(options: GenerateSignatureOptions): Promise<SignatureResult>;

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
/** Data input: string (di-encode UTF-8) atau bytes. */
type ECCData = string | Uint8Array;
/** Encode bytes ke base64. */
declare function bytesToBase64(bytes: Uint8Array): string;
/** Decode base64 ke bytes. */
declare function base64ToBytes(base64: string): Uint8Array<ArrayBuffer>;
/** Generate key pair ECDSA P-256 baru (extractable). */
declare function generateECCKeyPair(): Promise<CryptoKeyPair>;
/** Tandatangani `data` (SHA-256 + ECDSA). Hasil berupa signature ASN.1 DER. */
declare function signECC(privateKey: CryptoKey, data: ECCData): Promise<Uint8Array>;
/** Verifikasi signature ASN.1 DER dari `data`. */
declare function verifyECC(publicKey: CryptoKey, data: ECCData, signature: Uint8Array): Promise<boolean>;
/** Enkripsi `data` untuk pemilik `recipientPublicKey` (ECIES, AES-256-GCM). */
declare function encryptECC(recipientPublicKey: CryptoKey, data: ECCData): Promise<Uint8Array>;
/** Dekripsi data hasil `encryptECC`. */
declare function decryptECC(privateKey: CryptoKey, packedData: Uint8Array): Promise<Uint8Array>;
/** Export public key ke PEM (SPKI). Aman dikirim ke frontend. */
declare function exportPublicKeyAsPEM(publicKey: CryptoKey): Promise<string>;
/** Export private key ke PEM (PKCS#8). Simpan dengan aman, jangan dikirim ke frontend! */
declare function exportPrivateKeyAsPEM(privateKey: CryptoKey): Promise<string>;
/** Parse PEM (SPKI) menjadi public key ECDSA P-256. */
declare function parsePublicKeyFromPEM(pem: string): Promise<CryptoKey>;
/** Parse PEM (PKCS#8) menjadi private key ECDSA P-256. */
declare function parsePrivateKeyFromPEM(pem: string): Promise<CryptoKey>;

export { type ECCData, type GenerateSignatureOptions, type SignatureBody, type SignatureResult, base64ToBytes, bytesToBase64, capitalize, chunk, clamp, debounce, decryptECC, encryptECC, exportPrivateKeyAsPEM, exportPublicKeyAsPEM, formatRupiah, generateECCKeyPair, generateSignature, groupBy, parsePrivateKeyFromPEM, parsePublicKeyFromPEM, randomInt, signECC, sleep, slugify, truncate, unique, verifyECC };
