from __future__ import annotations

import base64
import binascii
import hashlib
import pickletools
import sqlite3
import urllib.request
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from flask import Blueprint, current_app, jsonify, request, session

from ..database import connect


blueprint = Blueprint("vulnerable", __name__)


def configure_app(app, _settings) -> None:
    app.config.update(
        SECRET_KEY="training-only-hard-coded-vulnerable-secret",
        SESSION_COOKIE_SECURE=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE=None,
    )


def password_hash(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest()  # noqa: S324 - deliberate lab flaw


def _settings():
    return current_app.config["FRX_SETTINGS"]


def _audit(message: str) -> None:
    with _settings().audit_log_path.open("a", encoding="utf-8") as stream:
        stream.write(message + "\n")


def _authenticated():
    if "user_id" not in session:
        return jsonify(error="Login required"), 401
    return None


@blueprint.get("/health")
def health():
    return jsonify(service="frx", state="vulnerable", status="ok")


@blueprint.post("/login")
def login():
    payload = request.get_json(silent=True) or request.form
    username = payload.get("username", "")
    password = payload.get("password", "")
    password_hash = hashlib.md5(password.encode("utf-8")).hexdigest()  # noqa: S324
    query = (
        "SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password_hash = '{password_hash}'"
    )
    _audit(f"LOGIN ATTEMPT username={username} password={password}")
    try:
        with connect(_settings().database_path) as connection:
            user = connection.execute(query).fetchone()
    except sqlite3.Error as error:
        return jsonify(error=str(error), query=query), 500
    if user is None:
        return jsonify(error="Invalid username or password", username=username), 401
    session.update(user_id=user["id"], username=user["username"], role=user["role"])
    _audit(f"LOGIN SUCCESS username={username} password={password}")
    return jsonify(user=dict(user))


@blueprint.post("/logout")
def logout():
    _audit(f"LOGOUT username={session.get('username')}")
    session.clear()
    return jsonify(status="logged-out")


@blueprint.get("/welcome")
def welcome():
    return f"<h1>Welcome, {request.args.get('name', 'researcher')}</h1>"


@blueprint.get("/reports/<int:report_id>")
def report_detail(report_id: int):
    if response := _authenticated():
        return response
    with connect(_settings().database_path) as connection:
        report = connection.execute(
            f"SELECT * FROM reports WHERE id = {report_id}"
        ).fetchone()
    if report is None:
        return jsonify(error="Report not found"), 404
    _audit(f"REPORT READ username={session.get('username')} report={report_id}")
    return jsonify(report=dict(report))


@blueprint.get("/search")
def search():
    if response := _authenticated():
        return response
    query_text = request.args.get("q", "")
    query = f"SELECT * FROM reports WHERE title LIKE '%{query_text}%' OR summary LIKE '%{query_text}%'"
    with connect(_settings().database_path) as connection:
        reports = [dict(row) for row in connection.execute(query).fetchall()]
    return jsonify(reports=reports, query=query)


@blueprint.post("/documents")
def upload_document():
    if response := _authenticated():
        return response
    uploaded = request.files["document"]
    # Preserve weak file-type and overwrite behavior without allowing a
    # learner-controlled path to escape the disposable runtime directory.
    client_name = PurePosixPath(uploaded.filename.replace("\\", "/")).name
    if not client_name:
        return jsonify(error="A document name is required"), 400
    destination = _settings().upload_root / client_name
    _settings().upload_root.mkdir(parents=True, exist_ok=True)
    uploaded.save(destination)
    _audit(f"UPLOAD username={session.get('username')} name={client_name}")
    return jsonify(stored_as=client_name), 201


@blueprint.post("/analytics/import")
def analytics_import():
    if response := _authenticated():
        return response
    try:
        decoded = base64.b64decode(request.get_data(), validate=True)
        opcodes = [opcode.name for opcode, _argument, _position in pickletools.genops(decoded)]
    except (binascii.Error, ValueError) as error:
        return jsonify(error="Invalid serialized training payload", detail=str(error)), 400
    executable_opcodes = sorted(
        set(opcodes)
        & {"BUILD", "EXT1", "EXT2", "EXT4", "GLOBAL", "INST", "NEWOBJ", "NEWOBJ_EX", "OBJ", "REDUCE", "STACK_GLOBAL"}
    )
    return (
        jsonify(
            accepted_format="python-pickle",
            dangerous_opcodes=executable_opcodes,
            executed=False,
        ),
        202,
    )


@blueprint.get("/analytics/fetch")
def analytics_fetch():
    if response := _authenticated():
        return response
    destination = request.args.get("url", "")
    allowed = urlsplit(_settings().analytics_base_url)
    requested = urlsplit(destination)
    if (
        requested.scheme != allowed.scheme
        or requested.hostname != allowed.hostname
        or requested.port != allowed.port
        or requested.username is not None
        or requested.password is not None
    ):
        return jsonify(error="Destination must use the local analytics fixture"), 400
    with urllib.request.urlopen(destination, timeout=2) as remote:  # noqa: S310
        payload = remote.read(64 * 1024).decode("utf-8")
    return current_app.response_class(payload, mimetype="application/json")


@blueprint.get("/errors/demo")
def error_demo():
    if response := _authenticated():
        return response
    return jsonify(error=f"Internal file missing: {Path(_settings().state_root, 'private', 'missing.txt')}", secret=current_app.secret_key), 500
