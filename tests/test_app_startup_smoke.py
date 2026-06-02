import pytest


def test_app_constructs_without_error():
    """Smoke test: constructing RPMEncrypterApp must not raise.

    __init__ builds every _create_*_frame eagerly, so this exercises all nine
    page builders and catches 'the app won't even start' bugs (e.g. an undefined
    variable in a frame builder) that the source-scan tests cannot see.

    It SKIPS (not fails) when there is no display (headless CI); any other
    exception (NameError, AttributeError, ...) is a real defect and fails.
    """
    import gui_app

    app = None
    try:
        app = gui_app.RPMEncrypterApp()
    except Exception as exc:  # noqa: BLE001 - we re-raise real code errors
        low = str(exc).lower()
        if "display" in low or "couldn't connect" in low or "no $display" in low:
            pytest.skip(f"No GUI display available: {exc}")
        raise
    finally:
        if app is not None:
            try:
                app.destroy()
            except Exception:
                pass
