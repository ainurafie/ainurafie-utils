/** Hapus duplikat dari array. */
export function unique<T>(arr: T[]): T[] {
  return [...new Set(arr)];
}

/** Pecah array jadi potongan berukuran `size`. */
export function chunk<T>(arr: T[], size: number): T[][] {
  const result: T[][] = [];
  for (let i = 0; i < arr.length; i += size) {
    result.push(arr.slice(i, i + size));
  }
  return result;
}

/** Kelompokkan item array berdasarkan key. */
export function groupBy<T, K extends PropertyKey>(
  arr: T[],
  getKey: (item: T) => K,
): Record<K, T[]> {
  return arr.reduce(
    (acc, item) => {
      const key = getKey(item);
      (acc[key] ||= []).push(item);
      return acc;
    },
    {} as Record<K, T[]>,
  );
}
