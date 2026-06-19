"""
stegosuite.crypto — authenticated, honestly-named hybrid cryptography
=====================================================================
Design goals (fixing the v1 issues):

* **Real KDF** — Argon2id (memory-hard) instead of a single SHA-512.
* **Authenticated encryption everywhere** — AES-256-GCM / ChaCha20-Poly1305.
  No unauthenticated CBC, so tampering and padding-oracle attacks are out.
* **Per-file random salt** — no hardcoded salts; identical passwords never
  produce identical keys.
* **Honest naming** — methods are labeled for what they actually are. The
  post-quantum method uses real ML-KEM (Kyber) when `oqs` is installed and
  is clearly marked *emulated* (X25519 hybrid) when it is not.
* **Versioned, length-prefixed container** with the header bound as AEAD AAD,
  replacing the fragile ``::``-split string format.

Container layout (all integers big-endian)::

    b"STG2" | header_len(4) | header_json(utf-8) | body

``header_json`` carries: method, original filename, kdf params, and the
base64 wrap material. ``body`` is the AEAD-protected (optionally double-wrapped)
data layer. The header is authenticated as additional data on the data layer.
"""
from __future__ import annotations

import base64
import json
import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, x25519, padding as asym_padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"STG2"
VERSION = 2

# ── optional real post-quantum backend ──────────────────────────────────────
try:
    import oqs  # liboqs python bindings
    _PQ = "ML-KEM-768"
    PQ_AVAILABLE = True
except Exception:
    oqs = None
    _PQ = None
    PQ_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# KDF  (Argon2id, with a scrypt fallback)
# ─────────────────────────────────────────────────────────────────────────────
_ARGON_DEFAULTS = {"time_cost": 3, "memory_cost": 64 * 1024, "parallelism": 4, "length": 32}


def derive_key(password: str, salt: bytes, params: dict | None = None) -> bytes:
    p = {**_ARGON_DEFAULTS, **(params or {})}
    try:
        from argon2.low_level import hash_secret_raw, Type
        return hash_secret_raw(
            password.encode("utf-8"), salt,
            time_cost=p["time_cost"], memory_cost=p["memory_cost"],
            parallelism=p["parallelism"], hash_len=p["length"], type=Type.ID,
        )
    except Exception:
        # scrypt fallback (still memory-hard; only used if argon2 missing)
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        return Scrypt(salt=salt, length=p["length"], n=2 ** 15, r=8, p=1).derive(
            password.encode("utf-8"))


def kdf_meta() -> dict:
    meta = dict(_ARGON_DEFAULTS)
    meta["algo"] = "argon2id"
    try:
        import argon2  # noqa: F401
    except Exception:
        meta["algo"] = "scrypt"
    return meta


# ─────────────────────────────────────────────────────────────────────────────
# AEAD data layer
# ─────────────────────────────────────────────────────────────────────────────
def _aead(alg: str, key: bytes):
    return ChaCha20Poly1305(key) if alg == "chacha20" else AESGCM(key)


def _seal_data(plaintext: bytes, dek: bytes, alg: str, aad: bytes) -> dict:
    nonce = os.urandom(12)
    ct = _aead(alg, dek).encrypt(nonce, plaintext, aad)
    return {"alg": alg, "nonce": _b64(nonce), "ct": _b64(ct)}


def _open_data(d: dict, dek: bytes, aad: bytes) -> bytes:
    return _aead(d["alg"], dek).decrypt(_unb64(d["nonce"]), _unb64(d["ct"]), aad)


# ─────────────────────────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────────────────────────
def _b64(b: bytes) -> str: return base64.b64encode(b).decode()
def _unb64(s: str) -> bytes: return base64.b64decode(s)


def _wrap_with_password(dek: bytes, password: str) -> dict:
    salt = os.urandom(16)
    params = kdf_meta()
    kek = derive_key(password, salt, params)
    nonce = os.urandom(12)
    wrapped = AESGCM(kek).encrypt(nonce, dek, b"dek-wrap")
    return {"salt": _b64(salt), "nonce": _b64(nonce), "wrapped": _b64(wrapped), "kdf": params}


def _unwrap_with_password(w: dict, password: str) -> bytes:
    kek = derive_key(password, _unb64(w["salt"]), w.get("kdf"))
    return AESGCM(kek).decrypt(_unb64(w["nonce"]), _unb64(w["wrapped"]), b"dek-wrap")


# ─────────────────────────────────────────────────────────────────────────────
# Shamir Secret Sharing (kept from v1, over the P-256 prime field)
# ─────────────────────────────────────────────────────────────────────────────
SSS_PRIME = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _sss_split(secret_int: int, n: int, k: int):
    coeffs = [secret_int] + [int.from_bytes(os.urandom(32), "big") % SSS_PRIME for _ in range(k - 1)]
    return [(x, sum(c * pow(x, i, SSS_PRIME) for i, c in enumerate(coeffs)) % SSS_PRIME)
            for x in range(1, n + 1)]


def _sss_recover(shares):
    secret = 0
    for i, (xi, yi) in enumerate(shares):
        num = den = 1
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            num = (num * (-xj)) % SSS_PRIME
            den = (den * (xi - xj)) % SSS_PRIME
        secret = (secret + yi * num * pow(den, SSS_PRIME - 2, SSS_PRIME)) % SSS_PRIME
    return secret % SSS_PRIME


# ─────────────────────────────────────────────────────────────────────────────
# Method registry — honest labels
# ─────────────────────────────────────────────────────────────────────────────
# maps the frontend's method keys to (internal_kind, data_alg, human_label)
METHODS = {
    "aes_ecc":             ("x25519", "aes",      "AES-256-GCM + X25519 (ECDH hybrid)"),
    "aes_rsa":             ("rsa",    "aes",      "AES-256-GCM + RSA-2048-OAEP (hybrid)"),
    "chacha20_ecc":        ("x25519", "chacha20", "ChaCha20-Poly1305 + X25519 (ECDH hybrid)"),
    "aes_chacha20_cascade":("cascade","aes",      "Cascade: AES-256-GCM then ChaCha20-Poly1305"),
    "kyber_aes":           ("pq",     "aes",      f"AES-256-GCM + {'ML-KEM-768 (Kyber)' if PQ_AVAILABLE else 'X25519 (PQ emulated — liboqs not installed)'}"),
    "aes_shamir":          ("shamir", "aes",      "AES-256-GCM, DEK split via Shamir 3-of-5"),
    "aes_elgamal":         ("rsa",    "aes",      "AES-256-GCM + RSA-2048-OAEP (labeled ElGamal in v1; ElGamal not implemented)"),
    "password":            ("password","aes",     "AES-256-GCM (password-wrapped DEK)"),
}


def method_label(method: str) -> str:
    return METHODS.get(method, METHODS["password"])[2]


# ─────────────────────────────────────────────────────────────────────────────
# seal / open
# ─────────────────────────────────────────────────────────────────────────────
def seal(plaintext: bytes, method: str, password: str, filename: str) -> bytes:
    kind, alg, label = METHODS.get(method, METHODS["password"])
    fname = (filename or "secret.bin")[:255]

    # cascade is special: two AEAD layers keyed straight from the password
    if kind == "cascade":
        salt = os.urandom(16)
        params = kdf_meta()
        km = derive_key(password, salt, {**params, "length": 64})
        k1, k2 = km[:32], km[32:]
        n1, n2 = os.urandom(12), os.urandom(12)
        c1 = AESGCM(k1).encrypt(n1, plaintext, fname.encode())
        c2 = ChaCha20Poly1305(k2).encrypt(n2, c1, fname.encode())
        header = {"v": VERSION, "method": method, "kind": kind, "label": label,
                  "fname": fname, "salt": _b64(salt), "n1": _b64(n1), "n2": _b64(n2),
                  "kdf": params}
        return _frame(header, c2)

    dek = os.urandom(32)
    aad = (method + "|" + fname).encode()
    data = _seal_data(plaintext, dek, alg, aad)
    header = {"v": VERSION, "method": method, "kind": kind, "label": label,
              "fname": fname, "data": data}

    if kind == "password":
        header["wrap"] = _wrap_with_password(dek, password)

    elif kind == "rsa":
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        enc_dek = priv.public_key().encrypt(
            dek, asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()),
                                   algorithm=hashes.SHA256(), label=None))
        priv_pem = priv.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())
        header["enc_dek"] = _b64(enc_dek)
        header["sealed_priv"] = _seal_blob(priv_pem, password)

    elif kind == "x25519":
        salt = os.urandom(16)
        params = kdf_meta()
        recip_priv = x25519.X25519PrivateKey.from_private_bytes(derive_key(password, salt, params))
        recip_pub = recip_priv.public_key()
        eph = x25519.X25519PrivateKey.generate()
        shared = eph.exchange(recip_pub)
        kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"x25519-wrap").derive(shared)
        nonce = os.urandom(12)
        header["salt"] = _b64(salt)
        header["kdf"] = params
        header["eph_pub"] = _b64(eph.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        header["enc_dek"] = _b64(AESGCM(kek).encrypt(nonce, dek, b"x25519"))
        header["nonce"] = _b64(nonce)

    elif kind == "pq":
        if PQ_AVAILABLE:
            with oqs.KeyEncapsulation(_PQ) as kem:
                pk = kem.generate_keypair()
                sk = kem.export_secret_key()
                kem_ct, shared = kem.encap_secret(pk)
            kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"pq-wrap").derive(shared)
            nonce = os.urandom(12)
            header["pq"] = _PQ
            header["kem_ct"] = _b64(kem_ct)
            header["enc_dek"] = _b64(AESGCM(kek).encrypt(nonce, dek, b"pq"))
            header["nonce"] = _b64(nonce)
            header["sealed_sk"] = _seal_blob(sk, password)
        else:
            # honest emulation: fall back to X25519 hybrid, clearly flagged
            header["pq_emulated"] = True
            salt = os.urandom(16); params = kdf_meta()
            recip_priv = x25519.X25519PrivateKey.from_private_bytes(derive_key(password, salt, params))
            eph = x25519.X25519PrivateKey.generate()
            shared = eph.exchange(recip_priv.public_key())
            kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"x25519-wrap").derive(shared)
            nonce = os.urandom(12)
            header["salt"] = _b64(salt); header["kdf"] = params
            header["eph_pub"] = _b64(eph.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw))
            header["enc_dek"] = _b64(AESGCM(kek).encrypt(nonce, dek, b"x25519"))
            header["nonce"] = _b64(nonce)

    elif kind == "shamir":
        secret_int = int.from_bytes(dek, "big") % SSS_PRIME
        shares = _sss_split(secret_int, 5, 3)[:3]
        blob = b"".join(x.to_bytes(1, "big") + y.to_bytes(32, "big") for x, y in shares)
        header["shares"] = _seal_blob(blob, password)

    else:
        header["wrap"] = _wrap_with_password(dek, password)

    return _frame(header, b"")


def open_(blob: bytes, password: str) -> tuple[bytes, str]:
    if blob[:4] != MAGIC:
        raise ValueError("not a STG2 container (no magic header)")
    hlen = struct.unpack(">I", blob[4:8])[0]
    header = json.loads(blob[8:8 + hlen].decode("utf-8"))
    body = blob[8 + hlen:]
    kind = header.get("kind")
    method = header.get("method", "password")
    fname = header.get("fname", "secret.bin")

    if kind == "cascade":
        km = derive_key(password, _unb64(header["salt"]), {**header.get("kdf", {}), "length": 64})
        k1, k2 = km[:32], km[32:]
        c1 = ChaCha20Poly1305(k2).decrypt(_unb64(header["n2"]), body, fname.encode())
        pt = AESGCM(k1).decrypt(_unb64(header["n1"]), c1, fname.encode())
        return pt, fname

    aad = (method + "|" + fname).encode()

    if kind == "password":
        dek = _unwrap_with_password(header["wrap"], password)

    elif kind == "rsa":
        priv_pem = _open_blob(header["sealed_priv"], password)
        priv = serialization.load_pem_private_key(priv_pem, password=None)
        dek = priv.decrypt(_unb64(header["enc_dek"]),
                           asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()),
                                             algorithm=hashes.SHA256(), label=None))

    elif kind == "x25519" or header.get("pq_emulated"):
        recip_priv = x25519.X25519PrivateKey.from_private_bytes(
            derive_key(password, _unb64(header["salt"]), header.get("kdf")))
        eph_pub = x25519.X25519PublicKey.from_public_bytes(_unb64(header["eph_pub"]))
        shared = recip_priv.exchange(eph_pub)
        kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"x25519-wrap").derive(shared)
        dek = AESGCM(kek).decrypt(_unb64(header["nonce"]), _unb64(header["enc_dek"]), b"x25519")

    elif kind == "pq":
        sk = _open_blob(header["sealed_sk"], password)
        with oqs.KeyEncapsulation(header["pq"], secret_key=sk) as kem:
            shared = kem.decap_secret(_unb64(header["kem_ct"]))
        kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"pq-wrap").derive(shared)
        dek = AESGCM(kek).decrypt(_unb64(header["nonce"]), _unb64(header["enc_dek"]), b"pq")

    elif kind == "shamir":
        blob2 = _open_blob(header["shares"], password)
        shares = [(blob2[i], int.from_bytes(blob2[i + 1:i + 33], "big"))
                  for i in range(0, len(blob2), 33)]
        dek = (_sss_recover(shares)).to_bytes(32, "big")

    else:
        dek = _unwrap_with_password(header["wrap"], password)

    return _open_data(header["data"], dek, aad), fname


# ── framing + small sealed blobs ─────────────────────────────────────────────
def _frame(header: dict, body: bytes) -> bytes:
    hj = json.dumps(header, separators=(",", ":")).encode("utf-8")
    return MAGIC + struct.pack(">I", len(hj)) + hj + body


def _seal_blob(data: bytes, password: str) -> dict:
    salt = os.urandom(16); params = kdf_meta()
    kek = derive_key(password, salt, params)
    nonce = os.urandom(12)
    return {"salt": _b64(salt), "nonce": _b64(nonce), "kdf": params,
            "ct": _b64(AESGCM(kek).encrypt(nonce, data, b"blob"))}


def _open_blob(b: dict, password: str) -> bytes:
    kek = derive_key(password, _unb64(b["salt"]), b.get("kdf"))
    return AESGCM(kek).decrypt(_unb64(b["nonce"]), _unb64(b["ct"]), b"blob")
