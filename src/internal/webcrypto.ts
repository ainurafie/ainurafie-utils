/** Web Crypto global, atau `node:crypto` untuk Node 18 yang belum punya global `crypto`. */
export async function getCrypto(): Promise<Crypto> {
  if (globalThis.crypto?.subtle) return globalThis.crypto;
  const specifier = "node:crypto";
  const mod = await import(/* @vite-ignore */ /* webpackIgnore: true */ specifier);
  return mod.webcrypto as Crypto;
}
