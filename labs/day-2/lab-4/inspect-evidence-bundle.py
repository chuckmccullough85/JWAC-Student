"""Read-only integrity and inventory check for the Day 2 Unit 6 bundle.

This helper validates the bound source and frozen artifact hashes and reports
mechanical inventory facts. It intentionally makes no security disposition.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


LAB = Path(__file__).resolve().parent
DEFAULT_BUNDLE = LAB / "evidence-bundle"
DEFAULT_ROOT = Path(__file__).resolve().parents[3]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    bundle = args.bundle.resolve()
    root = args.root.resolve()
    manifest = load_json(bundle / "pipeline-manifest.json")

    source_results = []
    for item in manifest["source_inputs"]:
        path = root / item["path"]
        actual = digest(path) if path.is_file() else None
        source_results.append(
            {
                "path": item["path"],
                "exists": path.is_file(),
                "hash_matches": actual == item["sha256"],
            }
        )

    artifact_results = []
    for relative, expected in manifest["artifact_hashes"].items():
        path = bundle / relative
        actual = digest(path) if path.is_file() else None
        artifact_results.append(
            {
                "path": relative,
                "exists": path.is_file(),
                "hash_matches": actual == expected,
            }
        )

    sast = load_json(bundle / "gl-sast-report.json")
    secrets = load_json(bundle / "gl-secret-detection-report.json")
    sbom = load_json(bundle / "frx.cdx.json")
    vulnerabilities = load_json(bundle / "frx_vulns.json")
    lock_entries = [
        line
        for line in (root / "requirements.txt").read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    result = {
        "pipeline_id": manifest["pipeline_id"],
        "baseline": manifest["baseline"],
        "application_state": manifest["application_state"],
        "source_integrity": all(
            item["exists"] and item["hash_matches"] for item in source_results
        ),
        "artifact_integrity": all(
            item["exists"] and item["hash_matches"] for item in artifact_results
        ),
        "source_results": source_results,
        "artifact_results": artifact_results,
        "sast_signals": len(sast["vulnerabilities"]),
        "secret_signals": len(secrets["vulnerabilities"]),
        "sbom_components": len(sbom["components"]),
        "resolved_lock_components": len(lock_entries),
        "sbom_composition": sbom["compositions"][0]["aggregate"],
        "frozen_advisories": len(vulnerabilities["vulnerabilities"]),
        "network_used": False,
        "dispositions_assigned": 0,
    }

    if args.as_json:
        print(json.dumps(result, indent=2))
    else:
        for key, value in result.items():
            if key not in {"source_results", "artifact_results"}:
                print(f"{key}: {value}")

    if not result["source_integrity"] or not result["artifact_integrity"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
