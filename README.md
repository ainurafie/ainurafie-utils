# ainurafie-utils

Kumpulan utility function TypeScript.

## Install

```bash
pnpm add github:ainurafie/ainurafie-utils
# versi tertentu
pnpm add github:ainurafie/ainurafie-utils#v0.2.0
```

## Pemakaian

```ts
import { slugify, formatRupiah, chunk, sleep } from "ainurafie-utils";

slugify("Halo Dunia!");   // "halo-dunia"
formatRupiah(15000);      // "Rp 15.000"
chunk([1, 2, 3, 4, 5], 2); // [[1, 2], [3, 4], [5]]
await sleep(500);
```

## Daftar function

| Modul  | Function |
| ------ | -------- |
| string | `capitalize`, `slugify`, `truncate` |
| number | `formatRupiah`, `clamp`, `randomInt` |
| array  | `unique`, `chunk`, `groupBy` |
| async  | `sleep`, `debounce` |
| signature | `generateSignature` |
| crypto | `generateECCKeyPair`, `signECC`, `verifyECC`, `encryptECC`, `decryptECC`, `exportPublicKeyAsPEM`, `exportPrivateKeyAsPEM`, `parsePublicKeyFromPEM`, `parsePrivateKeyFromPEM`, `bytesToBase64`, `base64ToBytes` |

## Signature NVX

Canonical: `METHOD + URI + X-Request-Id + X-App-Id + X-Platform + X-Timestamp + BODY TOKEN`, sama dengan
`RequiredSignaturePublicHeaders` default nvx-go-middleware. Body token: multipart `UNSIGNED`, body kosong `EMPTY`,
selain itu SHA256 byte body (termasuk binary).

```ts
const s = await generateSignature({ secret, appId, gatewayKey, method: "POST", url: "/iam/users/login", body });
await fetch(BASE_URL + "/iam/users/login", { method: s.method, headers: s.headers, body: s.body });
```

Kirim `s.headers` dan `s.body` apa adanya, karena body yang di-hash harus sama persis dengan yang dikirim.

## Development

```bash
pnpm install
pnpm build      # wajib sebelum commit, karena dist/ ikut di-commit
```

## Rilis versi baru

1. Ubah `version` di `package.json`
2. `pnpm build`
3. Commit, lalu `git tag v0.x.x && git push --tags`
