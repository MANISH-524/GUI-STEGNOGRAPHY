# 🔐 Secure StegoSuite v2 — Hybrid Cryptography + Steganography

A web app that **encrypts** a file with authenticated hybrid cryptography, then
**hides** the encrypted payload inside an ordinary-looking cover file (image,
audio, video, or text). v2 is a security-hardened rewrite of the original.

> ⚠️ **Authorized, lawful use only.** This is a privacy and educational tool.

---

## What's new in v2

This release fixes real security problems in v1 and makes the crypto claims
honest. Full write-up in **[SECURITY_REVIEW.md](./SECURITY_REVIEW.md)**.

| Area | v1 | v2 |
|---|---|---|
| Key derivation | single `sha512(pw+salt)` | **Argon2id** (memory-hard) + per-file salt |
| Encryption | unauthenticated AES-CBC | **AEAD** (AES-256-GCM / ChaCha20-Poly1305) |
| `/download` | path traversal | validated + `safe_join` + containment check |
| Flask | `debug=True`, `0.0.0.0` | debug off, localhost default, env-driven |
| "Kyber" method | not actually Kyber | **real ML-KEM** if `liboqs` present, else clearly-labeled X25519 fallback |
| Errors | silent fake-decrypt | clear failures; decoy is opt-in |
| Container | fragile `::` split | versioned, length-prefixed, AEAD-authenticated header |
| Stego stream | no integrity | magic marker + CRC32 + optional password-seeded scatter |
| CSRF / headers | none | same-origin guard + CSP & security headers |
| Tests | none | 26 pytest cases (crypto, stego, endpoints) |

---

## Encryption methods (honest names)

| UI key | What it actually is |
|---|---|
| `aes_ecc` | AES-256-GCM data key wrapped via **X25519 ECDH** hybrid |
| `aes_rsa` | AES-256-GCM data key wrapped via **RSA-2048-OAEP** |
| `chacha20_ecc` | ChaCha20-Poly1305 data + X25519 ECDH wrap |
| `aes_chacha20_cascade` | Two AEAD layers: AES-256-GCM **then** ChaCha20-Poly1305 |
| `kyber_aes` | AES-256-GCM + **ML-KEM-768 (Kyber)** when `liboqs` is installed; otherwise X25519, flagged *emulated* |
| `aes_shamir` | AES-256-GCM; data key split via **Shamir 3-of-5** |
| `aes_elgamal` | AES-256-GCM + **RSA-2048-OAEP** (v1 mislabeled this "ElGamal"; ElGamal isn't implemented) |

Cover media: images (`png`/`bmp`/`jpg`→PNG out), audio (`wav`), video (`mp4`/`avi`/`mkv`→FFV1 AVI out), text (zero-width chars).

---

## Install & run

```bash
git clone https://github.com/MANISH-524/GUI-STEGNOGRAPHY.git
cd GUI-STEGNOGRAPHY
pip install -r requirements.txt

cp .env.example .env        # set a strong STEGO_SECRET_KEY
python3 app.py              # dev → http://127.0.0.1:5000
```

Production:

```bash
gunicorn -w4 -b 0.0.0.0:5000 --timeout 300 app:app   # behind a TLS reverse proxy
# or
docker build -t stegosuite . && docker run -p 5000:5000 stegosuite
```

Run the tests:

```bash
pip install pytest && pytest -q          # 26 passing
```

---

## Architecture

```
app.py                 hardened Flask front end (routes, CSRF, headers, downloads)
stegosuite/
  crypto.py            Argon2id KDF · AEAD · hybrid wrappers · SSS · container format
  stego.py             LSB image/audio/video/text · magic+CRC · seeded scatter
templates/index.html   glassmorphism UI (unchanged)
tests/                 pytest round-trip + security regression suite
```

---

## Honest limitations
- **LSB is not undetectable** against modern statistical/ML steganalysis — it's
  obscurity layered on top of strong encryption, not a guarantee.
- Shamir shares are stored together (threshold is illustrative unless you
  distribute them).
- Auto-delete TTL is best-effort server hygiene, not secure disk erasure.

See **[SECURITY_REVIEW.md](./SECURITY_REVIEW.md)** for the complete analysis.

## Disclaimer
For educational, research, and legitimate privacy use only. The authors take no
responsibility for misuse.
