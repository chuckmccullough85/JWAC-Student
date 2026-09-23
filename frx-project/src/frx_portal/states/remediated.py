from __future__ import annotations

import json
import os
import secrets
import urllib.error
import urllib.request
import uuid
from pathlib import PurePosixPath

from flask import Blueprint, current_app, jsonify, render_template_string, request, session
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

from ..database import connect


blueprint = Blueprint("remediated", __name__)
ALLOWED_UPLOAD_EXTENSIONS = {".json", ".pdf", ".txt"}


def configure_app(app, settings) -> None:
    session_secret = os.environ.get("FRX_SESSION_SECRET")
    if not session_secret:
        if not settings.session_key_path.exists():
            settings.session_key_path.write_text(secrets.token_urlsafe(48), encoding="utf-8")
        session_secret = settings.session_key_path.read_text(encoding="utf-8").strip()
    app.config.update(
        SECRET_KEY=session_secret,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )


def password_hash(password: str) -> str:
    return generate_password_hash(password, method="scrypt")


def _settings():
    return current_app.config["FRX_SETTINGS"]


def _audit(event: str, outcome: str, **fields) -> None:
    safe_fields = " ".join(f"{key}={value}" for key, value in sorted(fields.items()))
    with _settings().audit_log_path.open("a", encoding="utf-8") as stream:
        stream.write(f"event={event} outcome={outcome} {safe_fields}".rstrip() + "\n")


def _authenticated():
    if "user_id" not in session:
        return jsonify(error="Login required"), 401
    return None


def _can_read(report) -> bool:
    role = session.get("role")
    user_id = session.get("user_id")
    return bool(
        role == "administrator"
        or (role == "partner" and report["owner_id"] == user_id)
        or (role == "analyst" and report["assigned_analyst_id"] == user_id)
    )


def _valid_upload(uploaded, suffix: str) -> bool:
    data = uploaded.stream.read(_settings().max_upload_bytes + 1)
    uploaded.stream.seek(0)
    if not data or len(data) > _settings().max_upload_bytes:
        return False
    if suffix == ".pdf":
        return data.startswith(b"%PDF-")
    if suffix == ".json":
        try:
            return isinstance(json.loads(data.decode("utf-8")), (dict, list))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return "\x00" not in decoded


@blueprint.get("/health")
def health():
    return jsonify(service="frx", state="remediated", status="ok")


@blueprint.post("/login")
def login():
    payload = request.get_json(silent=True) or request.form
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    if not (1 <= len(username) <= 64 and 1 <= len(password) <= 128):
        _audit("login", "failed", reason="invalid-input")
        return jsonify(error="Invalid username or password"), 401

    with connect(_settings().database_path) as connection:
        user = connection.execute(
            "SELECT id, username, password_hash, role, active FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if user is None or not user["active"] or not check_password_hash(user["password_hash"], password):
        _audit("login", "failed", username=username)
        return jsonify(error="Invalid username or password"), 401

    session.clear()
    session.update(user_id=user["id"], username=user["username"], role=user["role"])
    _audit("login", "success", username=user["username"])
    return jsonify(user={"id": user["id"], "username": user["username"], "role": user["role"]})


@blueprint.post("/logout")
def logout():
    username = session.get("username", "unknown")
    session.clear()
    _audit("logout", "success", username=username)
    return jsonify(status="logged-out")


@blueprint.get("/welcome")
def welcome():
    return render_template_string(
        "<h1>Welcome, {{ name }}</h1>", name=request.args.get("name", "researcher")
    )


@blueprint.get("/reports/<int:report_id>")
def report_detail(report_id: int):
    if response := _authenticated():
        return response
    with connect(_settings().database_path) as connection:
        report = connection.execute(
            "SELECT * FROM reports WHERE id = ?", (report_id,)
        ).fetchone()
    if report is None:
        return jsonify(error="Report not found"), 404
    if not _can_read(report):
        _audit("report-read", "denied", report_id=report_id, username=session["username"])
        return jsonify(error="Access denied"), 403
    _audit("report-read", "success", report_id=report_id, username=session["username"])
    return jsonify(report=dict(report))


@blueprint.get("/search")
def search():
    if response := _authenticated():
        return response
    query_text = request.args.get("q", "").strip()
    if len(query_text) > 80:
        return jsonify(error="Search text is too long"), 400
    with connect(_settings().database_path) as connection:
        rows = connection.execute(
            "SELECT * FROM reports WHERE title LIKE ? OR summary LIKE ?",
            (f"%{query_text}%", f"%{query_text}%"),
        ).fetchall()
    reports = [dict(row) for row in rows if _can_read(row)]
    return jsonify(reports=reports)


@blueprint.post("/documents")
def upload_document():
    if response := _authenticated():
        return response
    uploaded = request.files.get("document")
    if uploaded is None or not uploaded.filename:
        return jsonify(error="A document is required"), 400
    safe_name = secure_filename(uploaded.filename)
    suffix = PurePosixPath(safe_name).suffix.lower()
    if not safe_name or suffix not in ALLOWED_UPLOAD_EXTENSIONS:
        _audit("upload", "rejected", username=session["username"], reason="file-type")
        return jsonify(error="Unsupported document type"), 400
    if not _valid_upload(uploaded, suffix):
        _audit("upload", "rejected", username=session["username"], reason="content")
        return jsonify(error="Document content failed validation"), 400
    stored_name = f"{uuid.uuid4().hex}{suffix}"
    destination = (_settings().upload_root / stored_name).resolve()
    upload_root = _settings().upload_root.resolve()
    if upload_root not in destination.parents:
        return jsonify(error="Invalid storage path"), 400
    uploaded.save(destination)
    _audit("upload", "success", username=session["username"], stored_name=stored_name)
    return jsonify(stored_as=stored_name), 201


@blueprint.post("/analytics/import")
def analytics_import():
    if response := _authenticated():
        return response
    if request.mimetype != "application/json":
        return jsonify(error="Analytics data must be JSON"), 415
    try:
        value = request.get_json(force=False)
    except (TypeError, json.JSONDecodeError):
        return jsonify(error="Invalid analytics document"), 400
    if not isinstance(value, dict) or set(value) - {"report_id", "score", "category"}:
        return jsonify(error="Unexpected analytics fields"), 400
    if not isinstance(value.get("report_id"), int) or not isinstance(value.get("score"), (int, float)):
        return jsonify(error="Invalid analytics field types"), 400
    return jsonify(imported=value)


@blueprint.get("/analytics/fetch")
def analytics_fetch():
    if response := _authenticated():
        return response
    report_id = request.args.get("report_id", type=int)
    if report_id is None or report_id < 1:
        return jsonify(error="A positive report_id is required"), 400
    with connect(_settings().database_path) as connection:
        report = connection.execute(
            "SELECT * FROM reports WHERE id = ?", (report_id,)
        ).fetchone()
    if report is None:
        return jsonify(error="Report not found"), 404
    if not _can_read(report):
        _audit("analytics-fetch", "denied", report_id=report_id, username=session["username"])
        return jsonify(error="Access denied"), 403
    destination = f"{_settings().analytics_base_url}/metrics/{report_id}"
    try:
        with urllib.request.urlopen(destination, timeout=2) as remote:  # noqa: S310 - fixed configured origin
            payload = remote.read(64 * 1024)
    except (urllib.error.URLError, TimeoutError):
        _audit("analytics-fetch", "failed", report_id=report_id)
        return jsonify(error="Analytics provider unavailable"), 502
    try:
        decoded = json.loads(payload)
    except json.JSONDecodeError:
        return jsonify(error="Analytics provider returned invalid data"), 502
    if not isinstance(decoded, dict) or decoded.get("report_id") != report_id:
        return jsonify(error="Analytics response failed validation"), 502
    _audit("analytics-fetch", "success", report_id=report_id)
    return jsonify(decoded)


@blueprint.get("/errors/demo")
def error_demo():
    if response := _authenticated():
        return response
    _audit("demo-error", "handled", username=session["username"])
    return jsonify(error="The requested training resource is unavailable."), 503
