"""
stegosuite — secure hybrid cryptography + steganography (v2)
===========================================================
A hardened rewrite of the original single-file app's crypto/stego core:

* Argon2id KDF, AEAD everywhere, per-file salts, honest method naming.
* Self-describing LSB streams with CRC integrity + optional seeded scatter.
* Path-traversal-safe file handling and production-safe Flask config.
"""
from . import crypto, stego

__version__ = "2.0.0"
__all__ = ["crypto", "stego", "__version__"]
