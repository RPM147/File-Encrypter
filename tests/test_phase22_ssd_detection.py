from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _method_slice(source: str, method_name: str) -> str:
    marker = f"    def {method_name}"
    start = source.index(marker)
    next_def = source.find("\n    def ", start + len(marker))
    return source[start:] if next_def == -1 else source[start:next_def]


def test_wmic_is_replaced_with_powershell_get_physicaldisk():
    src = (ROOT / "views" / "settings_view.py").read_text(encoding="utf-8")
    assert "wmic" not in src
    body = _method_slice(src, "_run_health_check")
    assert "Get-PhysicalDisk" in body
    assert "powershell" in body


def test_ssd_detection_keeps_safe_fallback_and_linux_path():
    body = _method_slice((ROOT / "views" / "settings_view.py").read_text(encoding="utf-8"), "_run_health_check")
    # Safe default + broad catch => any failure falls back to "assume HDD".
    assert "is_ssd = False" in body
    assert "except Exception:" in body
    # Linux detection must remain intact.
    assert "/sys/block" in body
    assert "rotational" in body
    # Bounded so a hung query can't freeze the health check.
    assert "timeout=" in body
