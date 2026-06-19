# Security Review — Secure StegoSuite (v1 → v2)

This document records the issues found in the original `app.py` and how v2
addresses them. It is written to be honest about what the tool does and does
not provide, so the README's claims match the code.

## Critical

| # | Issue (v1) | Impact | Fix (v2) |
|---|---|---|---|
| 1 | **Path traversal in `/download/<filename>`** — filename passed straight to `os.path.join` + `send_file`. | An attacker could request `..%2f..%2fetc%2fpasswd` and read arbitrary server files. | Filename validated against a strict allowlist regex, resolved with `safe_join`, and confirmed to be **inside** the uploads dir before serving. |
| 2 | **`debug=True` + `host='0.0.0.0'`** | The Werkzeug interactive debugger allows **remote code execution** if the port is reachable. | Debug **off** by default; host defaults to `127.0.0.1`; both are env-controlled. Production runs under gunicorn. |
| 3 | **Weak key derivation** — keys were `sha512(password+salt)[:32]`, one fast hash. | Passwords are brute-forceable at billions/sec on a GPU. | **Argon2id** (memory-hard) with per-file random salt; scrypt fallback. |
| 4 | **Static salt** — ChaCha path used a hardcoded `b'chacha_salt_1234'`. | Same password → same key across all files; enables precomputation / dictionary attacks. | Every operation uses a fresh `os.urandom` salt stored in the container header. |
| 5 | **Unauthenticated AES-CBC** (no MAC). | Ciphertext is malleable; padding-oracle and tamper attacks possible. | All encryption is **AEAD** (AES-256-GCM / ChaCha20-Poly1305). Tampering fails loudly. |

## High

| # | Issue (v1) | Impact | Fix (v2) |
|---|---|---|---|
| 6 | **Mislabeled crypto** — `kyber_aes` contained no Kyber (ChaCha keyed by `sha3(password)`); `aes_elgamal` was actually RSA-PKCS1v15. | The "post-quantum" / "ElGamal" claims were false; PKCS1v15 is attackable. | Methods renamed to what they are. The PQ method uses **real ML-KEM (Kyber)** when `liboqs` is present and is explicitly marked *emulated (X25519 hybrid)* otherwise. RSA uses **OAEP-SHA256**. |
| 7 | **Silent fake-decryption** on any error returned a dummy file. | Masked wrong-password *and* tampering, and corrupted UX/debuggability. | Real failures now return a clear error. A decoy file is available only as an **opt-in** (`STEGO_DECOY=1`). |
| 8 | **No CSRF protection** on `POST /process`. | Cross-site form posts could drive the tool. | Same-origin (`Origin`/`Referer`) check on all POSTs; `SameSite=Strict` session cookie. |
| 9 | **Fragile `::`-split container** — filenames containing `::` corrupted parsing. | Crashes / ambiguous decode. | Versioned binary container: `MAGIC + len-prefixed JSON header + body`, header bound as AEAD AAD. |

## Medium

| # | Issue (v1) | Fix (v2) |
|---|---|---|
| 10 | Global mutable `ledger.json`, race conditions on concurrent writes. | Atomic write (`tmp` + `replace`) under a lock. |
| 11 | `mp3` in allowed audio set, but `wave` can't read MP3 → crash. | Audio LSB restricted to PCM `wav` with a clear error. |
| 12 | 1 GB upload limit (DoS). | Default 200 MB, env-tunable. |
| 13 | No integrity marker in stego stream → wrong files silently produced garbage. | LSB stream carries a magic marker + CRC32; non-stego files and wrong seeds are detected. |
| 14 | Missing security headers. | CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cache-Control: no-store`. |

## New defensive features in v2
- **Password-seeded LSB scatter** (image/audio): payload bits are spread across
  pseudo-random cover positions derived from the password, resisting naive
  sequential-LSB steganalysis. Sequential mode remains available when no seed
  is set.
- **Capacity pre-checks** with explicit byte counts in error messages.
- **Health endpoint** (`/healthz`) reporting version and whether real PQ is active.

## Honest limitations (please keep the README accurate)
- LSB steganography is **not** undetectable against modern statistical
  steganalysis (RS analysis, deep-learning detectors). It provides obscurity,
  not guarantees. Treat it as a layer, not a shield.
- The "Shamir 3-of-5" shares are stored together in one file, so the threshold
  is illustrative unless you actually distribute shares across parties.
- The auto-delete TTL is best-effort server-side hygiene, not a guarantee of
  unrecoverability on the underlying disk.
- This is a privacy/educational tool. Lawful, authorized use only.
