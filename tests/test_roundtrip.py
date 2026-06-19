"""
pytest suite for Secure StegoSuite v2.

Run:  pip install pytest && pytest -q
"""
import io
import os
import wave

import numpy as np
import pytest

from stegosuite import crypto, stego

PW = "correct horse battery staple"
SECRET = b"The eagle lands at dawn. " * 8
METHODS = ["aes_ecc", "aes_rsa", "chacha20_ecc", "aes_chacha20_cascade",
           "kyber_aes", "aes_shamir", "aes_elgamal", "password"]


# ── crypto ────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("method", METHODS)
def test_crypto_roundtrip(method):
    blob = crypto.seal(SECRET, method, PW, "secret.txt")
    out, name = crypto.open_(blob, PW)
    assert out == SECRET and name == "secret.txt"


@pytest.mark.parametrize("method", METHODS)
def test_wrong_password_fails(method):
    blob = crypto.seal(SECRET, method, PW, "secret.txt")
    with pytest.raises(Exception):
        crypto.open_(blob, "wrong-password")


def test_not_a_container():
    with pytest.raises(ValueError):
        crypto.open_(b"just some random bytes", PW)


def test_tamper_detected():
    blob = bytearray(crypto.seal(SECRET, "aes_ecc", PW, "s.txt"))
    blob[-1] ^= 0xFF                       # flip a ciphertext bit
    with pytest.raises(Exception):
        crypto.open_(bytes(blob), PW)


# ── stego ─────────────────────────────────────────────────────────────────────
def _payload():
    return crypto.seal(b"hidden", "aes_ecc", PW, "m.txt")


def test_image_roundtrip(tmp_path):
    import cv2
    p = _payload()
    cover = tmp_path / "c.png"
    cv2.imwrite(str(cover), (np.random.rand(200, 200, 3) * 255).astype(np.uint8))
    out = tmp_path / "s.png"
    stego.image_embed(str(cover), p, str(out), seed=PW)
    assert stego.image_extract(str(out), seed=PW) == p


def test_image_wrong_seed(tmp_path):
    import cv2
    cover = tmp_path / "c.png"
    cv2.imwrite(str(cover), (np.random.rand(200, 200, 3) * 255).astype(np.uint8))
    out = tmp_path / "s.png"
    stego.image_embed(str(cover), _payload(), str(out), seed=PW)
    with pytest.raises(ValueError):
        stego.image_extract(str(out), seed="different")


def test_wav_roundtrip(tmp_path):
    cover = tmp_path / "c.wav"
    with wave.open(str(cover), "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(8000)
        w.writeframes((np.random.rand(8000) * 30000 - 15000).astype("<i2").tobytes())
    p = _payload()
    out = tmp_path / "s.wav"
    stego.wav_embed(str(cover), p, str(out), seed=PW)
    assert stego.wav_extract(str(out), seed=PW) == p


def test_text_roundtrip():
    p = _payload()
    s = stego.text_embed("An ordinary sentence.", p)
    assert stego.text_extract(s) == p


def test_non_stego_detected(tmp_path):
    import cv2
    plain = tmp_path / "plain.png"
    cv2.imwrite(str(plain), (np.random.rand(50, 50, 3) * 255).astype(np.uint8))
    with pytest.raises(ValueError):
        stego.image_extract(str(plain), seed=PW)


def test_capacity_error(tmp_path):
    import cv2
    tiny = tmp_path / "tiny.png"
    cv2.imwrite(str(tiny), (np.random.rand(4, 4, 3) * 255).astype(np.uint8))
    big = b"x" * 100000
    with pytest.raises(ValueError):
        stego.image_embed(str(tiny), big, str(tmp_path / "o.png"))


# ── app endpoints ──────────────────────────────────────────────────────────────
@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("STEGO_UPLOAD_DIR", str(tmp_path / "up"))
    import importlib, app as A
    importlib.reload(A)
    return A.app.test_client()


def test_endpoint_traversal_blocked(client):
    for evil in ["..%2f..%2fetc%2fpasswd", "../app.py", "%2e%2e/app.py"]:
        assert client.get(f"/download/{evil}", follow_redirects=True).status_code in (400, 404)


def test_endpoint_cross_origin_blocked(client):
    assert client.post("/process", data={"mode": "encrypt"},
                       headers={"Origin": "http://evil.example"}).status_code == 403
