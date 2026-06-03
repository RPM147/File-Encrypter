import threading
from pathlib import Path

import app_config
from app_config import _load_cfg, push_recent, save_setting

ROOT = Path(app_config.__file__).resolve().parent


def test_config_has_a_mutation_lock_and_single_choke_point():
    assert hasattr(app_config, "_CONFIG_LOCK")
    assert callable(app_config._mutate_cfg)
    src = (ROOT / "app_config.py").read_text(encoding="utf-8")
    assert "_CONFIG_LOCK = threading.Lock()" in src
    assert "with _CONFIG_LOCK:" in src
    # push_recent / save_setting go through the choke point
    assert src.count("_mutate_cfg(") >= 2


def test_concurrent_setting_and_recent_updates_do_not_lose_each_other(tmp_path, monkeypatch):
    monkeypatch.setattr(app_config, "CONFIG_FILE", tmp_path / "cfg.json")

    n = 30
    barrier = threading.Barrier(2 * n)

    def write_setting(i):
        barrier.wait()
        save_setting(f"setting_{i}", i)

    def write_recent(i):
        barrier.wait()
        push_recent(f"recent_{i}", f"/p/{i}")

    threads = []
    for i in range(n):
        threads.append(threading.Thread(target=write_setting, args=(i,)))
        threads.append(threading.Thread(target=write_recent, args=(i,)))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    cfg = _load_cfg()
    settings = cfg.get("settings", {})
    for i in range(n):
        assert settings.get(f"setting_{i}") == i
        assert cfg.get(f"recent_{i}") == [f"/p/{i}"]


def test_all_config_writes_go_through_the_single_locked_choke_point():
    # After Phase 28 the ONLY place that calls _save_cfg(...) is _mutate_cfg in
    # app_config.py; every GUI/view mutation routes through _mutate_cfg.
    repo = ROOT
    for rel in ("gui_app.py", "views/library_view.py", "views/inspect_view.py", "views/settings_view.py"):
        src = (repo / rel).read_text(encoding="utf-8")
        assert "_save_cfg(" not in src, f"{rel} still calls _save_cfg directly"
        assert "_mutate_cfg(" in src, f"{rel} does not route config writes through _mutate_cfg"
