from __future__ import annotations

import argparse

from flask import Flask, jsonify


def create_fixture_app() -> Flask:
    app = Flask("frx-analytics-fixture")

    @app.get("/health")
    def health():
        return jsonify(service="frx-analytics-fixture", status="ok")

    @app.get("/metrics/<int:report_id>")
    def metrics(report_id: int):
        return jsonify(
            report_id=report_id,
            score=(report_id * 7) % 100,
            category="review-priority",
            source="local-fixture",
        )

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the FRX local analytics fixture")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=5101, type=int)
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "localhost"}:
        raise SystemExit("The training fixture may bind only to localhost.")
    create_fixture_app().run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
