from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_app_constants_has_the_app_and_container_values():
    import app_constants

    assert app_constants.APP_NAME == "RPM Encrypter"
    assert app_constants.APP_VERSION == "3.0.0"
    assert app_constants.CONTAINER_SIZE_CHOICES[0] == "Auto"
    assert app_constants.container_label_to_mb("1 GB") == 1024
    assert app_constants.container_label_to_mb("Auto") == 0
    assert app_constants.container_label_to_mb("100 MB") == 100


def test_gui_app_reexports_the_new_constants():
    import gui_app

    for name in ("APP_NAME", "APP_VERSION", "CONTAINER_SIZE_CHOICES", "container_label_to_mb"):
        assert hasattr(gui_app, name), name
    assert gui_app.APP_VERSION == "3.0.0"
    # MSG_QUEUE_SIZE stays defined in gui_app.
    assert hasattr(gui_app, "MSG_QUEUE_SIZE")


def test_moved_constant_defs_are_gone_from_gui_app():
    src = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    assert 'APP_NAME        = "RPM Encrypter"' not in src and 'APP_NAME = "RPM Encrypter"' not in src
    assert "CONTAINER_SIZE_CHOICES = [" not in src
    assert "def container_label_to_mb(" not in src
    assert "from app_constants import" in src
