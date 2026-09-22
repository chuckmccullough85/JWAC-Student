from __future__ import annotations

import pytest

from frx_portal import create_app
from frx_portal.config import Settings
from frx_portal.database import reset_database


@pytest.fixture
def app_factory(tmp_path):
    def build(state: str, analytics_base_url: str = "http://127.0.0.1:5101"):
        settings = Settings(
            state=state,
            runtime_root=tmp_path / "runtime",
            analytics_base_url=analytics_base_url,
        )
        reset_database(settings)
        app = create_app(state, settings)
        app.config.update(TESTING=True)
        return app, settings

    return build


def login(client, username="partner.alex", password="Fieldwork!23"):
    return client.post(
        "/login",
        json={"username": username, "password": password},
        base_url="https://localhost",
    )
