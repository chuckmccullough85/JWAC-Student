from __future__ import annotations

import argparse

from .app import create_app
from .config import VALID_STATES


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a local FRX training state")
    parser.add_argument("--state", choices=sorted(VALID_STATES), default="vulnerable")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=5100, type=int)
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "localhost"}:
        raise SystemExit("FRX training states may bind only to localhost.")

    app = create_app(args.state)
    print("WARNING: Local course application. Do not expose it publicly.")
    app.run(
        host=args.host,
        port=args.port,
        debug=False,
        ssl_context="adhoc" if args.state == "remediated" else None,
    )


if __name__ == "__main__":
    main()
