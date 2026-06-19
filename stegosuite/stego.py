"""
stegosuite.stego — hardened LSB steganography
=============================================
Improvements over v1:

* **Self-describing stream** — a magic marker + length + CRC32 is embedded
  ahead of the payload, so extraction can tell "this isn't a stego file" and
  verify integrity *before* decryption (instead of silently returning garbage).
* **Capacity checks** with clear errors for every medium.
* **Optional password-seeded bit positions** — when a seed is supplied, payload
  bits are scattered across pseudo-random cover positions, which defeats naive
  sequential LSB steganalysis. Extraction regenerates the same permutation.
* Lossless outputs enforced where LSB requires them (PNG images, FFV1 video,
  PCM WAV audio).
"""
from __future__ import annotations

import wave
import zlib

import numpy as np

LSB_MAGIC = b"LSB1"            # 4-byte marker → 32 bits, embedded sequentially
HEADER_BYTES = 4 + 4 + 4       # magic + uint32 length + uint32 crc32
HEADER_BITS = HEADER_BYTES * 8


# ─────────────────────────────────────────────────────────────────────────────
# core bit embedding over a flat uint8 array
# ─────────────────────────────────────────────────────────────────────────────
def _positions(n_cover: int, count: int, seed: str | None) -> np.ndarray:
    """Data-region positions (offset past the sequential header)."""
    region = np.arange(HEADER_BITS, n_cover)
    if count > len(region):
        raise ValueError("cover too small for payload")
    if not seed:
        return region[:count]
    import hashlib
    rng = np.random.default_rng(int.from_bytes(hashlib.sha256(seed.encode()).digest()[:8], "big"))
    perm = rng.permutation(len(region))
    return region[perm[:count]]


def embed_bytes(cover: bytes, payload: bytes, seed: str | None = None) -> bytes:
    arr = np.frombuffer(cover, dtype=np.uint8).copy()
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    head = LSB_MAGIC + len(payload).to_bytes(4, "big") + crc.to_bytes(4, "big")
    head_bits = np.unpackbits(np.frombuffer(head, dtype=np.uint8))
    data_bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))

    need = HEADER_BITS + len(data_bits)
    if need > len(arr):
        raise ValueError(f"cover too small: needs {need} LSBs, has {len(arr)} "
                         f"(payload {len(payload)} bytes)")
    # header → sequential
    arr[:HEADER_BITS] = (arr[:HEADER_BITS] & np.uint8(0xFE)) | head_bits
    # data → sequential or seeded-scatter
    pos = _positions(len(arr), len(data_bits), seed)
    arr[pos] = (arr[pos] & np.uint8(0xFE)) | data_bits
    return arr.tobytes()


def extract_bytes(stego: bytes, seed: str | None = None) -> bytes:
    arr = np.frombuffer(stego, dtype=np.uint8)
    if len(arr) < HEADER_BITS:
        raise ValueError("file too small to contain a stego header")
    head = np.packbits(arr[:HEADER_BITS] & 1).tobytes()
    if head[:4] != LSB_MAGIC:
        raise ValueError("no hidden data found (magic marker missing)")
    length = int.from_bytes(head[4:8], "big")
    crc = int.from_bytes(head[8:12], "big")
    pos = _positions(len(arr), length * 8, seed)
    payload = np.packbits(arr[pos] & 1).tobytes()[:length]
    if (zlib.crc32(payload) & 0xFFFFFFFF) != crc:
        raise ValueError("integrity check failed (CRC mismatch — wrong seed or tampering)")
    return payload


# ─────────────────────────────────────────────────────────────────────────────
# image (lossless PNG out)
# ─────────────────────────────────────────────────────────────────────────────
def image_embed(cover_path: str, payload: bytes, out_path: str, seed: str | None = None):
    import cv2
    img = cv2.imread(cover_path)
    if img is None:
        raise ValueError("invalid or unreadable image file")
    stego = embed_bytes(img.tobytes(), payload, seed)
    out = np.frombuffer(stego, dtype=np.uint8).reshape(img.shape)
    if not out_path.lower().endswith(".png"):
        out_path += ".png"
    cv2.imwrite(out_path, out)        # PNG = lossless, required for LSB survival
    return out_path


def image_extract(stego_path: str, seed: str | None = None) -> bytes:
    import cv2
    img = cv2.imread(stego_path)
    if img is None:
        raise ValueError("invalid or unreadable image file")
    return extract_bytes(img.tobytes(), seed)


# ─────────────────────────────────────────────────────────────────────────────
# audio (PCM WAV only)
# ─────────────────────────────────────────────────────────────────────────────
def wav_embed(cover_path: str, payload: bytes, out_path: str, seed: str | None = None):
    with wave.open(cover_path, "rb") as w:
        params = w.getparams()
        frames = w.readframes(w.getnframes())
    stego = embed_bytes(frames, payload, seed)
    with wave.open(out_path, "wb") as o:
        o.setparams(params)
        o.writeframes(stego)
    return out_path


def wav_extract(stego_path: str, seed: str | None = None) -> bytes:
    with wave.open(stego_path, "rb") as w:
        frames = w.readframes(w.getnframes())
    return extract_bytes(frames, seed)


# ─────────────────────────────────────────────────────────────────────────────
# video (lossless FFV1/AVI) — sequential across frame bytes
# ─────────────────────────────────────────────────────────────────────────────
def video_embed(cover_path: str, payload: bytes, out_path: str):
    import cv2
    cap = cv2.VideoCapture(cover_path)
    fps = cap.get(cv2.CAP_PROP_FPS) or 25
    w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    head = LSB_MAGIC + len(payload).to_bytes(4, "big") + crc.to_bytes(4, "big")
    bits = np.unpackbits(np.frombuffer(head + payload, dtype=np.uint8))

    fourcc = cv2.VideoWriter_fourcc(*"FFV1")
    if not out_path.lower().endswith(".avi"):
        out_path += ".avi"
    out = cv2.VideoWriter(out_path, fourcc, fps, (w, h))
    idx = 0
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break
        if idx < len(bits):
            flat = frame.flatten()
            chunk = min(len(flat), len(bits) - idx)
            flat[:chunk] = (flat[:chunk] & np.uint8(0xFE)) | bits[idx:idx + chunk]
            frame = flat.reshape(frame.shape)
            idx += chunk
        out.write(frame)
    cap.release(); out.release()
    if idx < len(bits):
        raise ValueError("video too short to hold the payload")
    return out_path


def video_extract(stego_path: str) -> bytes:
    import cv2
    cap = cv2.VideoCapture(stego_path)
    collected = []
    total = None
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break
        collected.append(frame.flatten() & 1)
        bits = np.concatenate(collected)
        if total is None and len(bits) >= HEADER_BITS:
            head = np.packbits(bits[:HEADER_BITS]).tobytes()
            if head[:4] != LSB_MAGIC:
                cap.release()
                raise ValueError("no hidden data found in video")
            length = int.from_bytes(head[4:8], "big")
            total = HEADER_BITS + length * 8
        if total is not None and len(bits) >= total:
            break
    cap.release()
    bits = np.concatenate(collected) if collected else np.array([], dtype=np.uint8)
    if total is None or len(bits) < total:
        raise ValueError("incomplete or missing data in video")
    head = np.packbits(bits[:HEADER_BITS]).tobytes()
    length = int.from_bytes(head[4:8], "big")
    crc = int.from_bytes(head[8:12], "big")
    payload = np.packbits(bits[HEADER_BITS:HEADER_BITS + length * 8]).tobytes()[:length]
    if (zlib.crc32(payload) & 0xFFFFFFFF) != crc:
        raise ValueError("video integrity check failed (CRC mismatch)")
    return payload


# ─────────────────────────────────────────────────────────────────────────────
# text (zero-width characters)
# ─────────────────────────────────────────────────────────────────────────────
_ZW0, _ZW1, _ZWEND = "\u200B", "\u200C", "\u200D"


def text_embed(cover_text: str, payload: bytes) -> str:
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    blob = LSB_MAGIC + len(payload).to_bytes(4, "big") + crc.to_bytes(4, "big") + payload
    bits = np.unpackbits(np.frombuffer(blob, dtype=np.uint8))
    hidden = "".join(_ZW0 if b == 0 else _ZW1 for b in bits) + _ZWEND
    cover_text = cover_text or " "
    return cover_text[0] + hidden + cover_text[1:]


def text_extract(stego_text: str) -> bytes:
    out = []
    for ch in stego_text:
        if ch == _ZW0:
            out.append(0)
        elif ch == _ZW1:
            out.append(1)
        elif ch == _ZWEND:
            break
    if not out:
        raise ValueError("no hidden data found in text")
    pad = (-len(out)) % 8
    arr = np.array(out + [0] * pad, dtype=np.uint8)
    blob = np.packbits(arr).tobytes()
    if blob[:4] != LSB_MAGIC:
        raise ValueError("no hidden data found (magic marker missing)")
    length = int.from_bytes(blob[4:8], "big")
    crc = int.from_bytes(blob[8:12], "big")
    payload = blob[12:12 + length]
    if (zlib.crc32(payload) & 0xFFFFFFFF) != crc:
        raise ValueError("text integrity check failed (CRC mismatch)")
    return payload


# ─────────────────────────────────────────────────────────────────────────────
# capacity helpers (for the UI to show before embedding)
# ─────────────────────────────────────────────────────────────────────────────
def image_capacity_bytes(cover_path: str) -> int:
    import cv2
    img = cv2.imread(cover_path)
    if img is None:
        return 0
    return max(0, (img.size - HEADER_BITS) // 8)


def wav_capacity_bytes(cover_path: str) -> int:
    with wave.open(cover_path, "rb") as w:
        n = len(w.readframes(w.getnframes()))
    return max(0, (n - HEADER_BITS) // 8)
