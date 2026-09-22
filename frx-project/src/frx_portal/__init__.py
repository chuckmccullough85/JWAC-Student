"""Field Research Exchange defensive-training application."""


def create_app(*args, **kwargs):
    from .app import create_app as app_factory

    return app_factory(*args, **kwargs)


__all__ = ["create_app"]
