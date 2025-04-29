import hashlib
import base64
import json
from bitarray import bitarray

# ======================
# Configurable Parameters
# ======================
filter_size = 512           # Increased size for better accuracy
hash_count = 3              # Number of hash functions

revoked_serials = [
     "google.com", "openai.com"
]

not_revoked_serials = [ 
    "apple.com", "microsoft.com", "mozilla.org",
    "amazon.com", "wikipedia.org", "example.com", "uic.edu",
    "linkedin.com", "cloudflare.com", "python.org", "stackoverflow.com",
    "docker.com", "firebase.google.com", "bbc.com", "cnn.com", "nytimes.com",
    "nasa.gov", "youtube.com", "duckduckgo.com", "netflix.com", "adobe.com",
    "protonmail.com"
]

# ======================
# Hash Function (SHA-256)
# ======================
def sha256_hash(key, seed):
    # combined = f"{key}-{seed}".encode()
    digest = hashlib.sha256(f"{key}-{seed}".encode()).digest()
    return int.from_bytes(digest[:4], byteorder='big')
    # digest = hashlib.sha256(combined).digest()
    # hash32 = int.from_bytes(digest[:4], byteorder='big')
    # return hash32
# ======================
# Bloom Filter Generator
# ======================
def base64_encode(text):
    return base64.b64encode(text.encode()).decode()

def create_bloom_filter(entries, size, hash_count):
    ba = bitarray(size)
    ba.setall(0)

    for entry in entries:
        key = base64_encode(entry)
        for i in range(hash_count):
            digest = sha256_hash(key, i) % size
            ba[digest] = 1
            print(f"SHA256 Hash {i}: bit {digest} set for {entry} → {key}")
    return ba.tolist()

# ======================
# Cascade Filter Assembly
# ======================
cascade = {
    "levels": [
        {
            "type": "blacklist",
            "size": filter_size,
            "hashCount": hash_count,
            "bitArray": create_bloom_filter(revoked_serials, filter_size, hash_count)
        },
        {
            "type": "whitelist",
            "size": filter_size,
            "hashCount": hash_count,
            "bitArray": create_bloom_filter(not_revoked_serials, filter_size, hash_count)
        }
    ]
}

# ======================
# Save to File
# ======================
with open("cascadeFilters.json", "w") as f:
    json.dump(cascade, f, indent=2)

print("✅ SHA-256 based cascadeFilters.json generated successfully.")