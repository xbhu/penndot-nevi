"""
Bundle build/tables/*.arrow (Arrow IPC streams) + build/meta.json into one AES-256-GCM encrypted file, with
per-user access (username + password).

  site/data/bundle.bin   = iv(12) || AES-GCM(DEK, plaintext)
  site/data/bundle.json  = {"v":3, "iter":N, "users": {sha256(username): {"salt":b64,"iv":b64,"wrapped":b64}}}

A random data key (DEK) encrypts the bundle once. For each user, the DEK is wrapped with
AES-GCM under KEK = PBKDF2-SHA256(username + ":" + password, salt). Usernames are stored only
as hashes. Adding / removing a user only changes bundle.json.

Plaintext layout (gzip-compressed):
  uint32 LE manifest_len || manifest JSON || concatenated Arrow IPC streams

Users come from pipeline/users.local.json (git-ignored):  {"nevi": "password", ...}

Usage: python3 pipeline/encrypt.py
Prints the Worker ACCESS_TOKENS secret: {"username": sha256("nevi-worker:user:password")}.
"""
import base64, gzip, hashlib, json, os, struct, sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ROOT = Path(__file__).resolve().parents[1]
TAB = ROOT / "build" / "tables"
OUT = ROOT / "site" / "data"
USERS = ROOT / "pipeline" / "users.local.json"
ITER = 600_000
b64 = lambda b: base64.b64encode(b).decode()

if not USERS.exists():
    sys.exit(f"missing {USERS} - create it as {{\"username\": \"password\"}}")
users = json.load(open(USERS))

tables, blobs, off = [], [], 0
for p in sorted(TAB.glob("*.arrow")):
    b = p.read_bytes()
    tables.append({"name": p.stem, "offset": off, "length": len(b)})
    blobs.append(b)
    off += len(b)
manifest = json.dumps({"meta": json.load(open(ROOT / "build" / "meta.json")), "tables": tables}).encode()
plain = gzip.compress(struct.pack("<I", len(manifest)) + manifest + b"".join(blobs), 9)

dek, iv = AESGCM.generate_key(256), os.urandom(12)
ct = AESGCM(dek).encrypt(iv, plain, None)

entries, tokens = {}, {}
for name, pw in users.items():
    name = name.strip().lower()
    salt, wiv = os.urandom(16), os.urandom(12)
    kek = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(f"{name}:{pw}".encode())
    entries[hashlib.sha256(name.encode()).hexdigest()] = {
        "salt": b64(salt), "iv": b64(wiv), "wrapped": b64(AESGCM(kek).encrypt(wiv, dek, None))}
    tokens[name] = hashlib.sha256(f"nevi-worker:{name}:{pw}".encode()).hexdigest()

OUT.mkdir(parents=True, exist_ok=True)
(OUT / "bundle.bin").write_bytes(iv + ct)
json.dump({"v": 3, "kdf": "PBKDF2-SHA256", "iter": ITER, "users": entries}, open(OUT / "bundle.json", "w"))
print(f"encrypted {len(plain)} B -> site/data/bundle.bin ({len(tables)} tables, {len(entries)} users)")
json.dump(tokens, open(ROOT / "build" / "access_tokens.json", "w"))
print("Worker secret ACCESS_TOKENS written to build/access_tokens.json")
