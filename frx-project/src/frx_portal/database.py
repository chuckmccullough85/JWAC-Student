from __future__ import annotations

import argparse
from importlib import import_module
import shutil
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .config import Settings, VALID_STATES


USERS = (
    (1, "partner.alex", "Fieldwork!23", "partner"),
    (2, "partner.jordan", "Maple!River9", "partner"),
    (3, "analyst.riley", "Evidence!42", "analyst"),
    (4, "admin.casey", "Review!84", "administrator"),
)

REPORTS = (
    (
        101,
        1,
        3,
        "Prairie Sensor Review",
        "partner-observation",
        "Sensor calibration drift exceeded tolerance during two afternoon collection windows.",
    ),
    (
        102,
        2,
        None,
        "Watershed Sampling Review",
        "partner-observation",
        "Chain-of-custody timestamps are incomplete for three watershed samples.",
    ),
    (
        103,
        2,
        3,
        "Remote Station Review",
        "partner-observation",
        "Intermittent power loss delayed uploads from the remote monitoring station.",
    ),
)


@contextmanager
def connect(database_path: Path) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _password_hash(password: str, state: str) -> str:
    state_module = import_module(f".states.{state}", __package__)
    return state_module.password_hash(password)


def reset_database(settings: Settings) -> None:
    state_root = settings.state_root.resolve()
    runtime_root = settings.runtime_root.resolve()
    if runtime_root not in state_root.parents:
        raise ValueError(f"Refusing to reset outside runtime root: {state_root}")

    if state_root.exists():
        shutil.rmtree(state_root)
    settings.upload_root.mkdir(parents=True, exist_ok=True)

    with connect(settings.database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE reports (
                id INTEGER PRIMARY KEY,
                owner_id INTEGER NOT NULL,
                assigned_analyst_id INTEGER,
                title TEXT NOT NULL,
                classification TEXT NOT NULL,
                summary TEXT NOT NULL,
                FOREIGN KEY(owner_id) REFERENCES users(id),
                FOREIGN KEY(assigned_analyst_id) REFERENCES users(id)
            );
            """
        )
        connection.executemany(
            "INSERT INTO users(id, username, password_hash, role) VALUES (?, ?, ?, ?)",
            [
                (user_id, username, _password_hash(password, settings.state), role)
                for user_id, username, password, role in USERS
            ],
        )
        connection.executemany(
            """
            INSERT INTO reports(id, owner_id, assigned_analyst_id, title, classification, summary)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            REPORTS,
        )

    settings.audit_log_path.write_text("FRX audit log initialized\n", encoding="utf-8")


def ensure_database(settings: Settings) -> None:
    if not settings.database_path.exists():
        reset_database(settings)


def main() -> None:
    parser = argparse.ArgumentParser(description="Reset the local FRX runtime data")
    parser.add_argument("--state", choices=[*sorted(VALID_STATES), "all"], default="all")
    args = parser.parse_args()

    states = sorted(VALID_STATES) if args.state == "all" else [args.state]
    for state in states:
        settings = Settings.from_environment(state)
        reset_database(settings)
        print(f"Reset {state}: {settings.state_root}")


if __name__ == "__main__":
    main()
