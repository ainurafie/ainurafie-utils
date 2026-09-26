/** Ubah huruf pertama jadi kapital. */
export function capitalize(str: string): string {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

/** Ubah teks jadi slug URL, contoh: "Halo Dunia!" -> "halo-dunia". */
export function slugify(str: string): string {
  return str
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9\s-]/g, "")
    .replace(/[\s-]+/g, "-")
    .replace(/^-|-$/g, "");
}

/** Potong teks jika melebihi panjang tertentu. */
export function truncate(str: string, length: number, suffix = "..."): string {
  return str.length > length ? str.slice(0, length) + suffix : str;
}
