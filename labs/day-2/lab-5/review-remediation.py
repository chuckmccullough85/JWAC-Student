"""Collect bounded before/after evidence for the FRX remediation review.

The runner uses temporary synthetic runtimes and Flask's in-process test client.
It starts no listener, makes no external network request, changes no repository
runtime, reveals no key material, and assigns no remediation disposition.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Callable
from unittest.mock import patch


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SOURCE_ROOT = REPOSITORY_ROOT / "frx-project" / "src"
if SOURCE_ROOT.is_dir():
    sys.path.insert(0, str(SOURCE_ROOT))

from frx_portal import create_app  # noqa: E402
from frx_portal.config import Settings  # noqa: E402
from frx_portal.database import connect, reset_database  # noqa: E402


BASE_URL = "https://localhost"
VULNERABLE_SOURCE = SOURCE_ROOT / "frx_portal/states/vulnerable.py"
REMEDIATED_SOURCE = SOURCE_ROOT / "frx_portal/states/remediated.py"
BUNDLE = Path(__file__).resolve().parent / "change-bundle"
MANIFEST = BUNDLE / "change-manifest.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def integrity_record() -> dict[str, object]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    source_results = {}
    artifact_results = {}
    for relative, expected in manifest["source_inputs"].items():
        path = REPOSITORY_ROOT / relative
        actual = sha256(path)
        source_results[relative] = {"matches": actual == expected, "sha256": actual}
    for relative, expected in manifest["evidence_artifacts"].items():
        path = REPOSITORY_ROOT / relative
        actual = sha256(path)
        artifact_results[relative] = {"matches": actual == expected, "sha256": actual}
    return {
        "change_bundle": manifest["change_bundle"],
        "before_baseline": manifest["before_baseline"],
        "proposed_state": manifest["proposed_state"],
        "source_integrity": all(item["matches"] for item in source_results.values()),
        "artifact_integrity": all(item["matches"] for item in artifact_results.values()),
        "source_inputs": source_results,
        "evidence_artifacts": artifact_results,
    }


def build_app(state: str, runtime_root: Path, analytics_base_url: str = "http://127.0.0.1:5101"):
    settings = Settings(
        state=state,
        runtime_root=runtime_root,
        analytics_base_url=analytics_base_url,
    )
    reset_database(settings)
    app = create_app(state, settings)
    app.config.update(TESTING=False, PROPAGATE_EXCEPTIONS=False)
    app.logger.disabled = True
    return app, settings


def login(client, username: str = "partner.alex", password: str = "Fieldwork!23"):
    return client.post(
        "/login",
        json={"username": username, "password": password},
        base_url=BASE_URL,
    )


def audit_text(settings: Settings) -> str:
    return settings.audit_log_path.read_text(encoding="utf-8")


def source_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def session_key(runtime_root: Path) -> dict[str, object]:
    vulnerable = source_text(VULNERABLE_SOURCE)
    remediated = source_text(REMEDIATED_SOURCE)
    app, settings = build_app("remediated", runtime_root / "primary")
    first_key = app.secret_key
    restarted = create_app("remediated", settings)
    second_key = restarted.secret_key
    fresh_app, _fresh_settings = build_app("remediated", runtime_root / "fresh")
    fresh_key = fresh_app.secret_key
    client = app.test_client()
    response = login(client)
    cookie = response.headers.get("Set-Cookie", "")
    body_text = response.get_data(as_text=True)
    return {
        "change_id": "PCH-001",
        "linked_finding": "FN1",
        "source_observations": {
            "fixed_assignment_present_before": 'SECRET_KEY="training-only-hard-coded-vulnerable-secret"' in vulnerable,
            "fixed_assignment_present_after": 'SECRET_KEY="training-only-hard-coded-vulnerable-secret"' in remediated,
            "environment_input_present_after": 'os.environ.get("FRX_SESSION_SECRET")' in remediated,
            "generated_fallback_present_after": "secrets.token_urlsafe(48)" in remediated,
        },
        "proof_observations": {
            "key_file_created": settings.session_key_path.is_file(),
            "key_length": len(first_key or ""),
            "key_persists_across_app_restart": first_key == second_key,
            "fresh_runtime_uses_distinct_key": first_key != fresh_key,
            "ordinary_login_status": response.status_code,
            "session_cookie_secure": "Secure" in cookie,
            "session_cookie_httponly": "HttpOnly" in cookie,
            "session_cookie_samesite_lax": "SameSite=Lax" in cookie,
            "key_material_returned_by_login": bool(first_key and str(first_key) in body_text),
            "no_session_report_status": app.test_client().get(
                "/reports/101", base_url=BASE_URL
            ).status_code,
        },
        "unresolved_evidence": [
            "production secret source and access policy",
            "file permission and backup handling",
            "rotation, revocation, and previous-session transition",
            "operational deployment configuration",
        ],
    }


def login_and_password(runtime_root: Path) -> dict[str, object]:
    vulnerable_app, vulnerable_settings = build_app("vulnerable", runtime_root / "vulnerable")
    remediated_app, remediated_settings = build_app("remediated", runtime_root / "remediated")
    vulnerable_client = vulnerable_app.test_client()
    remediated_client = remediated_app.test_client()

    with connect(vulnerable_settings.database_path) as connection:
        vulnerable_hash = connection.execute(
            "SELECT password_hash FROM users WHERE username = ?", ("partner.alex",)
        ).fetchone()["password_hash"]
    with connect(remediated_settings.database_path) as connection:
        remediated_hash = connection.execute(
            "SELECT password_hash FROM users WHERE username = ?", ("partner.alex",)
        ).fetchone()["password_hash"]

    wrong_password = "ordinary-wrong-password"
    vulnerable_valid = login(vulnerable_client)
    remediated_valid = login(remediated_client)
    vulnerable_wrong = login(vulnerable_app.test_client(), password=wrong_password)
    remediated_wrong = login(remediated_app.test_client(), password=wrong_password)
    vulnerable_quote = login(
        vulnerable_app.test_client(), username="missing'user", password=wrong_password
    )
    remediated_quote = login(
        remediated_app.test_client(), username="missing'user", password=wrong_password
    )
    vulnerable_log = audit_text(vulnerable_settings)
    remediated_log = audit_text(remediated_settings)
    remediated = source_text(REMEDIATED_SOURCE)
    return {
        "change_id": "PCH-002",
        "source_observations": {
            "password_uses_scrypt_after": 'generate_password_hash(password, method="scrypt")' in remediated,
            "login_query_is_parameterized_after": "WHERE username = ?" in remediated,
            "session_cleared_before_identity_update": "session.clear()" in remediated,
        },
        "proof_observations": {
            "before_hash_shape": "32-character hexadecimal",
            "after_hash_scheme": remediated_hash.split(":", 1)[0],
            "before_valid_login_status": vulnerable_valid.status_code,
            "after_valid_login_status": remediated_valid.status_code,
            "before_wrong_password_status": vulnerable_wrong.status_code,
            "after_wrong_password_status": remediated_wrong.status_code,
            "before_quote_boundary_status": vulnerable_quote.status_code,
            "after_quote_boundary_status": remediated_quote.status_code,
            "before_log_contains_submitted_password": wrong_password in vulnerable_log,
            "after_log_contains_submitted_password": wrong_password in remediated_log,
            "after_log_records_failed_event": "event=login outcome=failed" in remediated_log,
            "before_hash_is_32_hex": len(vulnerable_hash) == 32
            and all(character in "0123456789abcdef" for character in vulnerable_hash),
        },
        "unresolved_evidence": [
            "production identity provider and password policy",
            "credential migration and forced-reset plan",
            "rate limiting, lockout, and monitoring ownership",
        ],
    }


def report_authorization(runtime_root: Path) -> dict[str, object]:
    vulnerable_app, _vulnerable_settings = build_app("vulnerable", runtime_root / "vulnerable")
    remediated_app, _remediated_settings = build_app("remediated", runtime_root / "remediated")

    vulnerable_alex = vulnerable_app.test_client()
    login(vulnerable_alex)
    before_other = vulnerable_alex.get("/reports/102", base_url=BASE_URL).status_code

    cases = [
        ("anonymous", None, None, 101),
        ("partner-own", "partner.alex", "Fieldwork!23", 101),
        ("partner-other", "partner.alex", "Fieldwork!23", 102),
        ("partner-second-own", "partner.jordan", "Maple!River9", 102),
        ("analyst-assigned", "analyst.riley", "Evidence!42", 101),
        ("analyst-unassigned", "analyst.riley", "Evidence!42", 102),
        ("administrator", "admin.casey", "Review!84", 102),
        ("missing-object", "partner.alex", "Fieldwork!23", 999),
    ]
    matrix = []
    for label, username, password, report_id in cases:
        client = remediated_app.test_client()
        login_status = None
        if username is not None and password is not None:
            login_status = login(client, username=username, password=password).status_code
        response = client.get(f"/reports/{report_id}", base_url=BASE_URL)
        matrix.append(
            {
                "case": label,
                "login_status": login_status,
                "report_id": report_id,
                "status": response.status_code,
            }
        )
    remediated = source_text(REMEDIATED_SOURCE)
    return {
        "change_id": "PCH-003",
        "source_observations": {
            "shared_can_read_helper_present": "def _can_read(report)" in remediated,
            "report_route_calls_can_read": "if not _can_read(report):" in remediated,
            "denial_is_audited": '_audit("report-read", "denied"' in remediated,
        },
        "proof_observations": {
            "before_partner_other_status": before_other,
            "after_actor_resource_action_matrix": matrix,
        },
        "unresolved_evidence": [
            "external policy-owner confirmation of role and assignment rules",
            "enforcement consistency on interfaces outside the tested report route",
            "production identity and assignment-data integrity",
        ],
    }


class FakeRemote:
    def __init__(self, payload: bytes):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc_value, _traceback):
        return False

    def read(self, _limit: int) -> bytes:
        return self.payload


def analytics_destination(runtime_root: Path) -> dict[str, object]:
    base_url = "http://127.0.0.1:5101"
    vulnerable_app, _vulnerable_settings = build_app(
        "vulnerable", runtime_root / "vulnerable", analytics_base_url=base_url
    )
    remediated_app, _remediated_settings = build_app(
        "remediated", runtime_root / "remediated", analytics_base_url=base_url
    )
    called_destinations: list[str] = []

    def fake_urlopen(destination, timeout=0):
        called_destinations.append(str(destination))
        report_id = int(str(destination).rstrip("/").split("/")[-1])
        return FakeRemote(
            json.dumps(
                {"report_id": report_id, "score": 42, "source": "local-fixture"}
            ).encode("utf-8")
        )

    vulnerable_client = vulnerable_app.test_client()
    login(vulnerable_client)
    remediated_client = remediated_app.test_client()
    login(remediated_client)
    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        before_selected_url = vulnerable_client.get(
            "/analytics/fetch",
            query_string={"url": f"{base_url}/metrics/101"},
            base_url=BASE_URL,
        ).status_code
        after_selected_url = remediated_client.get(
            "/analytics/fetch",
            query_string={"url": f"{base_url}/metrics/101"},
            base_url=BASE_URL,
        ).status_code
        after_owned = remediated_client.get(
            "/analytics/fetch", query_string={"report_id": 101}, base_url=BASE_URL
        ).status_code
        after_other = remediated_client.get(
            "/analytics/fetch", query_string={"report_id": 102}, base_url=BASE_URL
        ).status_code
        after_invalid = remediated_client.get(
            "/analytics/fetch", query_string={"report_id": 0}, base_url=BASE_URL
        ).status_code
        after_anonymous = remediated_app.test_client().get(
            "/analytics/fetch", query_string={"report_id": 101}, base_url=BASE_URL
        ).status_code
    remediated = source_text(REMEDIATED_SOURCE)
    return {
        "change_id": "PCH-004",
        "source_observations": {
            "caller_url_input_removed_after": 'request.args.get("url"' not in remediated,
            "positive_report_id_required_after": 'request.args.get("report_id", type=int)' in remediated,
            "authorization_checked_before_outbound_call": remediated.find("if not _can_read(report)")
            < remediated.find("urllib.request.urlopen(destination"),
            "destination_constructed_from_configured_origin": 'f"{_settings().analytics_base_url}/metrics/{report_id}"' in remediated,
        },
        "proof_observations": {
            "before_caller_selected_fixture_url_status": before_selected_url,
            "after_caller_url_parameter_status": after_selected_url,
            "after_owned_report_status": after_owned,
            "after_other_report_status": after_other,
            "after_invalid_report_id_status": after_invalid,
            "after_no_session_status": after_anonymous,
            "configured_destinations_called": called_destinations,
            "network_listener_started": False,
            "external_network_used": False,
        },
        "unresolved_evidence": [
            "production service identity, TLS, DNS, proxy, and egress controls",
            "provider response authenticity and availability objectives",
            "interfaces outside the tested analytics route",
        ],
    }


def audit_and_errors(runtime_root: Path) -> dict[str, object]:
    vulnerable_app, vulnerable_settings = build_app("vulnerable", runtime_root / "vulnerable")
    remediated_app, remediated_settings = build_app("remediated", runtime_root / "remediated")
    vulnerable_client = vulnerable_app.test_client()
    remediated_client = remediated_app.test_client()
    login(vulnerable_client)
    login(remediated_client)
    vulnerable_error = vulnerable_client.get("/errors/demo", base_url=BASE_URL)
    remediated_error = remediated_client.get("/errors/demo", base_url=BASE_URL)
    vulnerable_body = vulnerable_error.get_json() or {}
    remediated_body = remediated_error.get_json() or {}
    known_password = "Fieldwork!23"
    return {
        "change_id": "PCH-005",
        "proof_observations": {
            "before_audit_contains_submitted_password": known_password in audit_text(vulnerable_settings),
            "after_audit_contains_submitted_password": known_password in audit_text(remediated_settings),
            "after_audit_records_login_success": "event=login outcome=success" in audit_text(remediated_settings),
            "before_error_status": vulnerable_error.status_code,
            "after_error_status": remediated_error.status_code,
            "before_error_contains_key_field": "secret" in vulnerable_body,
            "after_error_contains_key_field": "secret" in remediated_body,
            "before_error_mentions_internal_file": "missing.txt" in str(vulnerable_body.get("error", "")),
            "after_error_mentions_internal_file": "missing.txt" in str(remediated_body.get("error", "")),
        },
        "unresolved_evidence": [
            "central collection, access control, retention, and tamper protection",
            "alert routing and operations response evidence",
            "unhandled exception behavior in the delivery deployment",
        ],
    }


SCENARIOS: dict[str, Callable[[Path], dict[str, object]]] = {
    "session-key": session_key,
    "login-and-password": login_and_password,
    "report-authorization": report_authorization,
    "analytics-destination": analytics_destination,
    "audit-and-errors": audit_and_errors,
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect bounded FRX remediation-review evidence."
    )
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="session-key")
    parser.add_argument("--list", action="store_true", help="List available scenarios.")
    parser.add_argument("--all", action="store_true", help="Run every scenario.")
    parser.add_argument(
        "--integrity-only", action="store_true", help="Check the bound change bundle only."
    )
    args = parser.parse_args()

    if args.list:
        print("\n".join(sorted(SCENARIOS)))
        return

    integrity = integrity_record()
    if args.integrity_only:
        print(json.dumps(integrity, indent=2, sort_keys=True))
        return

    names = sorted(SCENARIOS) if args.all else [args.scenario]
    result: dict[str, object] = {
        "before_baseline": "vulnerable",
        "proposed_state": "remediated",
        "runner": "temporary in-process Flask test clients with mocked outbound response",
        "network_listener_started": False,
        "external_network_used": False,
        "repository_runtime_modified": False,
        "secret_material_returned": False,
        "remediation_disposition_assigned": False,
        "integrity": integrity,
        "scenarios": {},
    }
    with tempfile.TemporaryDirectory(prefix="frx-unit7-") as temporary:
        temporary_root = Path(temporary)
        for name in names:
            result["scenarios"][name] = SCENARIOS[name](temporary_root / name)

    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
