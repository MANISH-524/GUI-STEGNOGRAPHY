#!/usr/bin/env python3
"""
Secure StegoSuite v2 — hardened Flask front end
===============================================
Drop-in replacement for the v1 ``app.py`` with the same routes/UI, fixing the
v1 security issues:

* `/download` is path-traversal-safe (filenames validated + resolved under uploads).
* Debug is OFF by default; host/port/limits/secret come from the environment.
* Same-origin (CSRF) check on POST; security headers on every response.
* Argon2id + AEAD crypto and integrity-checked stego (see stegosuite/).
* Atomic, locked ledger; explicit (opt-in) decoy mode instead of silent
  fake-decryption that masked real errors.

Run:  python3 app.py            (dev)
      gunicorn -w4 app:app      (prod, behind TLS)
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
import zlib
from pathlib import Path

from flask import (Flask, render_template, request, send_file, jsonify, abort)
from werkzeug.utils import secure_filename, safe_join

from stegosuite import crypto, stego

# ─────────────────────────────────────────────────────────────────────────────
# config (env-driven)
# ─────────────────────────────────────────────────────────────────────────────
UPLOAD_FOLDER = Path(os.environ.get("STEGO_UPLOAD_DIR", "uploads")).resolve()
MAX_MB = int(os.environ.get("STEGO_MAX_MB", "200"))
DECRYPT_TTL = int(os.environ.get("STEGO_DECRYPT_TTL", "300"))    # seconds
GENERAL_TTL = int(os.environ.get("STEGO_FILE_TTL", "3600"))
DECOY_ON_FAIL = os.environ.get("STEGO_DECOY", "0") == "1"        # opt-in, off by default
ALLOW_DOWNLOAD = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,128}$")

UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config.update(
    MAX_CONTENT_LENGTH=MAX_MB * 1024 * 1024,
    SECRET_KEY=os.environ.get("STEGO_SECRET_KEY", os.urandom(32).hex()),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
)

ALLOWED = {
    "audio_audio": {"cover": {"wav"},               "out": "wav"},
    "audio_image": {"cover": {"png", "bmp", "jpg", "jpeg"}, "out": "png"},
    "audio_video": {"cover": {"mp4", "avi", "mkv"}, "out": "avi"},
    "text_text":   {"cover": {"txt", "md", "csv"},  "out": "txt"},
}
_ledger_lock = threading.Lock()


def _ext_ok(filename, allowed):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed


def _save_upload(file_storage):
    name = secure_filename(file_storage.filename) or f"upload_{uuid.uuid4().hex[:8]}"
    dest = UPLOAD_FOLDER / name
    file_storage.save(dest)
    return dest


# ─────────────────────────────────────────────────────────────────────────────
# security middleware
# ─────────────────────────────────────────────────────────────────────────────
@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'")
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.before_request
def csrf_same_origin():
    if request.method == "POST":
        origin = request.headers.get("Origin")
        referer = request.headers.get("Referer", "")
        host = request.host
        if origin and origin.split("://")[-1] != host:
            abort(403, "cross-origin POST blocked")
        if not origin and referer and host not in referer:
            abort(403, "cross-origin POST blocked")


@app.before_request
def cleanup_old_files():
    now = time.time()
    for f in UPLOAD_FOLDER.iterdir():
        if not f.is_file() or f.name == "ledger.json":
            continue
        try:
            age = now - f.stat().st_ctime
            ttl = DECRYPT_TTL if "_decrypted" in f.name else GENERAL_TTL
            if age > ttl:
                f.unlink()
        except OSError:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# ledger (atomic + locked)
# ─────────────────────────────────────────────────────────────────────────────
def _ledger_path():
    return UPLOAD_FOLDER / "ledger.json"


def ledger_add(file_hash):
    with _ledger_lock:
        p = _ledger_path()
        data = []
        if p.exists():
            try:
                data = json.loads(p.read_text())
            except Exception:
                data = []
        if file_hash not in data:
            data.append(file_hash)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(data))
        tmp.replace(p)


def ledger_has(file_hash):
    with _ledger_lock:
        p = _ledger_path()
        if not p.exists():
            return False
        try:
            return file_hash in json.loads(p.read_text())
        except Exception:
            return False


def sha256_of(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# routes
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/process", methods=["POST"])
def process():
    try:
        mode = request.form.get("mode", "encrypt")
        password = request.form.get("password", "")
        method = request.form.get("method", "aes_ecc")
        action = request.form.get("action_type", "audio_image")
        if action not in ALLOWED:
            return jsonify({"error": f"unsupported action_type: {action}"}), 400
        if not password:
            return jsonify({"error": "password required"}), 400

        if mode == "encrypt":
            cover = request.files.get("cover")
            secret = request.files.get("secret")
            if not cover or not secret:
                return jsonify({"error": "missing cover or secret file"}), 400
            if not _ext_ok(cover.filename, ALLOWED[action]["cover"]):
                return jsonify({"error": "cover must be one of "
                                f"{sorted(ALLOWED[action]['cover'])} for {action}"}), 400

            cover_path = _save_upload(cover)
            secret_path = _save_upload(secret)
            payload = crypto.seal(
                zlib.compress(secret_path.read_bytes(), 9),
                method, password, secret.filename)

            out_name = f"output_{uuid.uuid4().hex[:8]}"
            out_path = UPLOAD_FOLDER / f"{out_name}.{ALLOWED[action]['out']}"

            if action == "audio_audio":
                stego.wav_embed(str(cover_path), payload, str(out_path), seed=password)
            elif action == "audio_image":
                out_path = Path(stego.image_embed(str(cover_path), payload,
                                                  str(out_path), seed=password))
            elif action == "audio_video":
                out_path = Path(stego.video_embed(str(cover_path), payload, str(out_path)))
            elif action == "text_text":
                cover_text = cover_path.read_text(encoding="utf-8", errors="ignore")
                out_path.write_text(stego.text_embed(cover_text, payload), encoding="utf-8")

            ledger_add(sha256_of(out_path))
            return jsonify({
                "success": True,
                "method": crypto.method_label(method),
                "download_url": f"/download/{out_path.name}",
                "message": "Encrypted and embedded successfully.",
            })

        elif mode == "decrypt":
            stego_file = request.files.get("stego")
            if not stego_file:
                return jsonify({"error": "missing stego file"}), 400
            stego_path = _save_upload(stego_file)

            try:
                if action == "audio_audio":
                    payload = stego.wav_extract(str(stego_path), seed=password)
                elif action == "audio_image":
                    payload = stego.image_extract(str(stego_path), seed=password)
                elif action == "audio_video":
                    payload = stego.video_extract(str(stego_path))
                elif action == "text_text":
                    payload = stego.text_extract(
                        stego_path.read_text(encoding="utf-8", errors="ignore"))
            except ValueError as e:
                return jsonify({"error": f"extraction failed: {e}"}), 400

            integrity = ledger_has(sha256_of(stego_path))

            try:
                decrypted, original = crypto.open_(payload, password)
                data = zlib.decompress(decrypted)
            except Exception:
                if DECOY_ON_FAIL:
                    data = b"REPORT: routine status. Nothing of interest. End of file."
                    original = "status_report.txt"
                else:
                    return jsonify({"error": "decryption failed — wrong password "
                                    "or the data was tampered with"}), 400

            out_name = f"_decrypted_{uuid.uuid4().hex[:8]}_{secure_filename(original)}"
            out_path = UPLOAD_FOLDER / out_name
            out_path.write_bytes(data)
            return jsonify({
                "success": True,
                "integrity_verified": integrity,
                "download_url": f"/download/{out_path.name}",
                "message": f"Extracted: {original}",
            })

        return jsonify({"error": "invalid mode"}), 400

    except Exception:
        app.logger.exception("process failed")
        return jsonify({"error": "internal error"}), 500


@app.route("/download/<path:filename>")
def download(filename):
    if not ALLOW_DOWNLOAD.match(filename):
        abort(400, "invalid filename")
    joined = safe_join(str(UPLOAD_FOLDER), filename)
    if not joined:
        abort(400, "invalid path")
    resolved = Path(joined).resolve()
    if not str(resolved).startswith(str(UPLOAD_FOLDER) + os.sep) or not resolved.is_file():
        abort(404)
    return send_file(resolved, as_attachment=True, download_name=resolved.name)


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok", "version": "2.0.0",
                    "pq_available": crypto.PQ_AVAILABLE})


if __name__ == "__main__":
    debug = os.environ.get("STEGO_DEBUG", "0") == "1"
    host = os.environ.get("STEGO_HOST", "127.0.0.1")   # localhost by default (was 0.0.0.0)
    port = int(os.environ.get("STEGO_PORT", "5000"))
    if debug:
        print("WARNING: debug mode enabled — never expose this to a network.")
    app.run(host=host, port=port, debug=debug)
