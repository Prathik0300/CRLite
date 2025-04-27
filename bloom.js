async function sha256Hash(key, seed) {
  const encoder = new TextEncoder();
  const data = encoder.encode(`${key}-${seed}`);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));

  // Only use first 4 bytes = 32 bits = safe integer
  const hash32 =
    (hashArray[0] << 24) |
    (hashArray[1] << 16) |
    (hashArray[2] << 8) |
    hashArray[3];
  return hash32 >>> 0; // convert to unsigned 32-bit int
}

async function checkBloomFilter(bitArray, size, hashCount, key) {
  for (let i = 0; i < hashCount; i++) {
    const hash = await sha256Hash(key, i);
    const index = hash % size;
    console.log({ index, hash });
    if (bitArray[index] === 0) return false;
  }
  return true;
}

async function checkCascade(key, filters) {
  for (let i = 0; i < filters.levels.length; i++) {
    const level = filters.levels[i];
    console.log({
      type: level.type,
      l1: level["bitArray"][101],
      l2: level["bitArray"][44],
      l3: level["bitArray"][158],
    });
    const present = await checkBloomFilter(
      level.bitArray,
      level.size,
      level.hashCount,
      key
    );

    if (!present) {
      return level.type === "blacklist" ? "Not Revoked" : "Revoked";
    }
  }

  const lastLevel = filters.levels.at(-1);
  return lastLevel.type === "blacklist" ? "Revoked" : "Not Revoked";
}
