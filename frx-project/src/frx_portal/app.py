from __future__ import annotations

from importlib import import_module
import traceback

from flask import Flask, jsonify, render_template

from .config import Settings
from .database import ensure_database


def create_app(state: str = "vulnerable", settings: Settings | None = None) -> Flask:
    settings = settings or Settings.from_environment(state)
    ensure_database(settings)

    app = Flask(__name__)
    app.config.update(
        FRX_SETTINGS=settings,
        MAX_CONTENT_LENGTH=settings.max_upload_bytes,
    )

    state_module = import_module(f".states.{state}", __package__)
    state_module.configure_app(app, settings)
    app.register_blueprint(state_module.blueprint)

    @app.get("/")
    def sample_client():
        return render_template("index.html")

    @app.errorhandler(413)
    def content_too_large(_error):
        return jsonify(error="Request is larger than the training limit."), 413

    @app.errorhandler(500)
    def internal_error(error):
        if state == "vulnerable":
            return jsonify(error=str(error), traceback=traceback.format_exc()), 500
        app.logger.exception("Unhandled FRX request failure")
        return jsonify(error="The request could not be completed."), 500

    return app
