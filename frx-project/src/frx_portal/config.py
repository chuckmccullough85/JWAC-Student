from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


VALID_STATES = {"vulnerable"}
if (Path(__file__).with_name("states").joinpath("remediated.py")).is_file():
    VALID_STATES.add("remediated")


@dataclass(frozen=True)
class Settings:
    state: str
    runtime_root: Path
    analytics_base_url: str = "http://127.0.0.1:5101"
    max_upload_bytes: int = 256 * 1024

    def __post_init__(self) -> None:
        if self.state not in VALID_STATES:
            raise ValueError(f"Unknown application state: {self.state}")
        analytics = urlsplit(self.analytics_base_url)
        if analytics.scheme not in {"http", "https"} or analytics.hostname not in {
            "127.0.0.1",
            "localhost",
            "::1",
        }:
            raise ValueError("Analytics fixture must use a loopback HTTP(S) origin.")

    @property
    def state_root(self) -> Path:
        return self.runtime_root / self.state

    @property
    def database_path(self) -> Path:
        return self.state_root / "frx.db"

    @property
    def upload_root(self) -> Path:
        return self.state_root / "uploads"

    @property
    def audit_log_path(self) -> Path:
        return self.state_root / "audit.log"

    @property
    def session_key_path(self) -> Path:
        return self.state_root / "session.key"

    @classmethod
    def from_environment(cls, state: str) -> "Settings":
        default_runtime = Path(__file__).resolve().parents[2] / "runtime"
        return cls(
            state=state,
            runtime_root=Path(os.environ.get("FRX_RUNTIME_ROOT", default_runtime)),
            analytics_base_url=os.environ.get(
                "FRX_ANALYTICS_BASE_URL", "http://127.0.0.1:5101"
            ).rstrip("/"),
        )
