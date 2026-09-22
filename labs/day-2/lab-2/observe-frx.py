"""Run bounded, in-process observations against the FRX learner baseline.

The runner uses a temporary runtime directory and the supplied synthetic
fixtures. It does not start a network listener or modify repository runtime
data. Output is observation data, not a finding or checklist decision.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import pickle
import sys
import tempfile
from pathlib import Path
from typing import Callable


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SOURCE_ROOT = REPOSITORY_ROOT / "case-study" / "src"
if SOURCE_ROOT.is_dir():
    sys.path.insert(0, str(SOURCE_ROOT))

from frx_portal import create_app  # noqa: E402
from frx_portal.config import Settings  # noqa: E402
from frx_portal.database import reset_database  # noqa: E402


BASE_URL = "https://localhost"
BASELINE = "vulnerable"


def build_app(runtime_root: Path):
    settings = Settings(
        state=BASELINE,
        runtime_root=runtime_root,
        analytics_base_url="http://127.0.0.1:5101",
    )
    reset_database(settings)
    app = create_app(BASELINE, settings)
    app.config.update(TESTING=False, PROPAGATE_EXCEPTIONS=False)
    app.logger.disabled = True
    return app, settings


def login(client, username: str = "partner.alex", password: str = "Fieldwork!23"):
    return client.post(
        "/login",
        json={"username": username, "password": password},
        base_url=BASE_URL,
    )


def response_record(label: str, response) -> dict[str, object]:
    record: dict[str, object] = {
        "label": label,
        "status": response.status_code,
        "content_type": response.content_type,
    }
    body = response.get_json(silent=True)
    if isinstance(body, dict):
        record["body_keys"] = sorted(body)
        for key in ("error", "query", "stored_as", "accepted_format", "executed"):
            if key in body:
                record[key] = body[key]
        if isinstance(body.get("report"), dict):
            report = body["report"]
            record["report"] = {
                key: report.get(key)
                for key in ("id", "owner_id", "assigned_analyst_id", "title")
            }
        if isinstance(body.get("reports"), list):
            record["report_ids"] = [item.get("id") for item in body["reports"]]
            record["report_count"] = len(body["reports"])
        if isinstance(body.get("dangerous_opcodes"), list):
            record["dangerous_opcodes"] = body["dangerous_opcodes"]
    else:
        record["text"] = response.get_data(as_text=True)
    return record


def audit_lines(settings) -> list[str]:
    return settings.audit_log_path.read_text(encoding="utf-8").splitlines()


def report_access(runtime_root: Path) -> dict[str, object]:
    app, settings = build_app(runtime_root)
    client = app.test_client()
    observations = [
        response_record(
            "no-session GET /reports/101",
            client.get("/reports/101", base_url=BASE_URL),
        ),
        response_record("login partner.alex", login(client)),
        response_record(
            "partner.alex GET /reports/101",
            client.get("/reports/101", base_url=BASE_URL),
        ),
        response_record(
            "partner.alex GET /reports/102",
            client.get("/reports/102", base_url=BASE_URL),
        ),
        response_record(
            "partner.alex GET /reports/999",
            client.get("/reports/999", base_url=BASE_URL),
        ),
    ]
    return {"observations": observations, "audit_lines": audit_lines(settings)}


def search_boundary(runtime_root: Path) -> dict[str, object]:
    app, settings = build_app(runtime_root)
    client = app.test_client()
    login(client)
    observations = []
    for label, query in (
        ("owned-title term", "Prairie"),
        ("other-owner title term", "Watershed"),
        ("ordinary punctuation", "O'Reilly"),
        ("empty term", ""),
    ):
        response = client.get(
            "/search", query_string={"q": query}, base_url=BASE_URL
        )
        observations.append(response_record(f"{label}: q={query!r}", response))
    return {"observations": observations, "audit_lines": audit_lines(settings)}


def document_repeat(runtime_root: Path) -> dict[str, object]:
    app, settings = build_app(runtime_root)
    client = app.test_client()
    login(client)
    first = client.post(
        "/documents",
        data={"document": (io.BytesIO(b"first synthetic field note\n"), "field-note.txt")},
        content_type="multipart/form-data",
        base_url=BASE_URL,
    )
    stored_name = first.get_json()["stored_as"]
    stored_path = settings.upload_root / stored_name
    first_hash = hashlib.sha256(stored_path.read_bytes()).hexdigest()
    second = client.post(
        "/documents",
        data={"document": (io.BytesIO(b"second synthetic field note\n"), "field-note.txt")},
        content_type="multipart/form-data",
        base_url=BASE_URL,
    )
    second_hash = hashlib.sha256(stored_path.read_bytes()).hexdigest()
    return {
        "observations": [
            response_record("first field-note.txt submission", first),
            response_record("second field-note.txt submission", second),
        ],
        "stored_files": sorted(path.name for path in settings.upload_root.iterdir()),
        "sha256_after_first": first_hash,
        "sha256_after_second": second_hash,
        "audit_lines": audit_lines(settings),
    }


def login_audit(runtime_root: Path) -> dict[str, object]:
    app, settings = build_app(runtime_root)
    client = app.test_client()
    failed = login(client, password="ordinary-wrong-password")
    succeeded = login(client)
    return {
        "observations": [
            response_record("failed partner.alex login", failed),
            response_record("successful partner.alex login", succeeded),
        ],
        "audit_lines": audit_lines(settings),
    }


def error_response(runtime_root: Path) -> dict[str, object]:
    app, settings = build_app(runtime_root)
    client = app.test_client()
    login(client)
    response = client.get("/errors/demo", base_url=BASE_URL)
    record = response_record("authenticated GET /errors/demo", response)
    body = response.get_json(silent=True)
    if isinstance(body, dict):
        observed_error = str(body.get("error", ""))
        state_root = str(settings.state_root)
        record["contains_runtime_path"] = state_root in observed_error
        sanitized_body = dict(body)
        sanitized_body["error"] = observed_error.replace(
            state_root, "<temporary-runtime>/vulnerable"
        )
        record["error"] = sanitized_body["error"]
        record["body"] = sanitized_body
    return {"observations": [record], "audit_lines": audit_lines(settings)}


def welcome_output(runtime_root: Path) -> dict[str, object]:
    app, settings = build_app(runtime_root)
    client = app.test_client()
    response = client.get(
        "/welcome", query_string={"name": "R&D <West>"}, base_url=BASE_URL
    )
    return {
        "observations": [response_record("GET /welcome with R&D <West>", response)],
        "audit_lines": audit_lines(settings),
    }


def analytics_format(runtime_root: Path) -> dict[str, object]:
    app, settings = build_app(runtime_root)
    client = app.test_client()
    login(client)
    benign_value = {"report_id": 101, "score": 42}
    encoded = base64.b64encode(pickle.dumps(benign_value))
    response = client.post(
        "/analytics/import", data=encoded, base_url=BASE_URL
    )
    return {
        "observations": [response_record("benign analytics value", response)],
        "audit_lines": audit_lines(settings),
    }


SCENARIOS: dict[str, Callable[[Path], dict[str, object]]] = {
    "report-access": report_access,
    "search-boundary": search_boundary,
    "document-repeat": document_repeat,
    "login-audit": login_audit,
    "error-response": error_response,
    "welcome-output": welcome_output,
    "analytics-format": analytics_format,
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run bounded FRX learner-baseline observations."
    )
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="report-access")
    parser.add_argument("--list", action="store_true", help="List available scenarios.")
    parser.add_argument("--all", action="store_true", help="Run every scenario.")
    args = parser.parse_args()

    if args.list:
        print("\n".join(sorted(SCENARIOS)))
        return

    names = sorted(SCENARIOS) if args.all else [args.scenario]
    result: dict[str, object] = {
        "baseline": BASELINE,
        "runner": "in-process Flask test client",
        "network_listener_started": False,
        "repository_runtime_modified": False,
        "scenarios": {},
    }
    with tempfile.TemporaryDirectory(prefix="frx-unit4-") as temporary:
        temporary_root = Path(temporary)
        for name in names:
            result["scenarios"][name] = SCENARIOS[name](temporary_root)

    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
