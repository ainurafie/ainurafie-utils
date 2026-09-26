/** Format angka ke Rupiah, contoh: 15000 -> "Rp 15.000". */
export function formatRupiah(value: number, withSymbol = true): string {
  const formatted = new Intl.NumberFormat("id-ID", {
    maximumFractionDigits: 0,
  }).format(value);
  return withSymbol ? `Rp ${formatted}` : formatted;
}

/** Batasi angka di antara min dan max. */
export function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

/** Angka acak bulat antara min dan max (inklusif). */
export function randomInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
