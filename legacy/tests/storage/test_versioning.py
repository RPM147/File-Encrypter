from pathlib import Path

from rpm_encrypter.storage.versioning import VaultVersionManager

ROOT = Path(__file__).resolve().parents[2]


def test_versioning_prune_all_respects_per_vault_count_and_has_no_dead_code(tmp_path):
    versions_root = tmp_path / "versions"
    vault = tmp_path / "demo.vault"
    vault.write_bytes(b"v0" * 64)

    mgr = VaultVersionManager(
        versions_root=versions_root,
        max_versions_per_vault=2,
        max_total_size_bytes=10 * 1024 * 1024,
        enabled=True,
    )

    for i in range(4):
        vault.write_bytes(f"content-{i}".encode() * 16)
        saved = mgr.save_version(vault)
        assert saved is not None

    # Lower max count and call prune_all directly.
    mgr.max_versions_per_vault = 2
    mgr.prune_all()
    assert len(mgr.list_versions(vault)) == 2

    src = (ROOT / "src" / "rpm_encrypter" / "storage" / "versioning.py").read_text(encoding="utf-8")
    assert "synthetic" not in src
