// SHA256-based hash function
async function sha256Hash(key, seed) {
  const encoder = new TextEncoder();
  const data = encoder.encode(`${key}-${seed}`);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));

  const hash32 =
    (hashArray[0] << 24) |
    (hashArray[1] << 16) |
    (hashArray[2] << 8) |
    hashArray[3];
  return hash32 >>> 0; // Unsigned 32-bit
}

// Check inside a single bloom filter
async function checkBloomFilter(bitArray, size, hashCount, key) {
  for (let i = 0; i < hashCount; i++) {
    const hash = await sha256Hash(key, i);
    const index = hash % size;
    if (bitArray[index] === 0) return false;
  }
  return true;
}

// Check cascade of filters (static cascadeFilters.json)
async function checkCascade(key, filters) {
  for (let i = 0; i < filters.levels.length; i++) {
    const level = filters.levels[i];
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

// 🛡️ Now actually define BloomFilter class (dynamic memory filter)

class BloomFilter {
  constructor(size = 1000, hashCount = 4) {
    this.size = size;
    this.hashCount = hashCount;
    this.bitArray = Array(size).fill(0);
  }

  async add(item) {
    for (let i = 0; i < this.hashCount; i++) {
      const hash = await sha256Hash(item, i);
      const index = hash % this.size;
      this.bitArray[index] = 1;
    }
  }

  async has(item) {
    for (let i = 0; i < this.hashCount; i++) {
      const hash = await sha256Hash(item, i);
      const index = hash % this.size;
      if (this.bitArray[index] === 0) return false;
    }
    return true;
  }

  saveAsJSON() {
    return {
      size: this.size,
      hashCount: this.hashCount,
      bitArray: this.bitArray,
    };
  }

  static fromJSON(json) {
    const bloom = new BloomFilter(json.size, json.hashCount);
    bloom.bitArray = json.bitArray;
    return bloom;
  }
}

// ✅ Attach functions to global scope so background.js can use it
self.BloomFilter = BloomFilter;
self.sha256Hash = sha256Hash;
self.checkCascade = checkCascade;
self.checkBloomFilter = checkBloomFilter;
