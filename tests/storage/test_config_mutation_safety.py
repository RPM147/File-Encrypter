import threading
from pathlib import Path

from rpm_encrypter.storage import config as app_config
from rpm_encrypter.storage.config import _load_cfg, push_recent, save_setting

ROOT = Path(__file__).resolve().parents[2]


def test_config_has_a_mutation_lock_and_single_choke_point():
    assert hasattr(app_config, "_CONFIG_LOCK")
    assert callable(app_config._mutate_cfg)
    src = (ROOT / "src" / "rpm_encrypter" / "storage" / "config.py").read_text(encoding="utf-8")
    assert "_CONFIG_LOCK = threading.Lock()" in src
    assert "with _CONFIG_LOCK:" in src
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
    pkg_dir = ROOT / "src" / "rpm_encrypter"
    config_file = pkg_dir / "storage" / "config.py"
    storage_init = pkg_dir / "storage" / "__init__.py"
    for py in sorted(pkg_dir.rglob("*.py")):
        if py in (config_file, storage_init):
            continue
        src = py.read_text(encoding="utf-8")
        assert "_save_cfg(" not in src, f"{py.relative_to(ROOT)} calls _save_cfg directly"
