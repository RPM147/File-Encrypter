"""Presentation helpers for InspectScreen metadata and fingerprint rows."""

import flet as ft

from rpm_encrypter.ui.components import empty_text
from rpm_encrypter.ui.tokens import COLORS, SPACING, TYPE


def format_vault_metadata(metadata: dict) -> str:
    """Render decrypted vault header metadata and file manifest lines."""
    mb = metadata.get("total_size", metadata.get("original_size", 0)) / (1024 * 1024)
    lines = [
        "=" * 55,
        "VAULT METADATA",
        "=" * 55,
        "",
        f"Original Name   : {metadata.get('filename', 'N/A')}",
        f"Original Size   : {metadata.get('original_size', 0):,} bytes ({mb:.2f} MiB)",
        f"File Count      : {metadata.get('file_count', 'N/A')}",
        f"Created         : {metadata.get('created_at', 'N/A')}",
        f"Source Type     : {metadata.get('source_type', 'N/A')}",
        "",
        "-" * 55,
        "CRYPTOGRAPHIC PARAMETERS",
        "-" * 55,
        "",
        f"KDF Algorithm   : {metadata.get('kdf_algorithm', 'N/A')}",
        f"Envelope Cipher : {metadata.get('encryption', 'N/A')}",
        f"Payload Cipher  : {metadata.get('payload_encryption', 'N/A')}",
        "",
        f"Argon2 Memory   : {metadata.get('argon_memory', 'N/A')} KiB",
        f"Argon2 Iters    : {metadata.get('argon_iterations', 'N/A')}",
        f"Argon2 Parallel : {metadata.get('argon_parallelism', 'N/A')}",
        "",
        "=" * 55,
    ]
    files = metadata.get("files", [])
    if files:
        lines += ["", "FILE MANIFEST", "-" * 55, ""]
        for fi in files[:100]:
            lines.append(f"- {fi.get('path', '')} ({fi.get('size', 0):,} bytes)")
        if len(files) > 100:
            lines.append(f"... and {len(files) - 100} more files")
        lines += ["", "=" * 55]
    return "\n".join(lines)


def build_fingerprint_rows(fps: dict) -> list[ft.Control]:
    """Build Flet list controls for saved vault SHA-256 fingerprints."""
    if not fps:
        return [empty_text("No fingerprints saved yet.")]

    rows: list[ft.Control] = []
    for key, rec in sorted(
        fps.items(), key=lambda kv: kv[1].get("recorded", ""), reverse=True
    ):
        sz_mb = rec.get("size", 0) / (1024 * 1024)
        sha16 = rec.get("sha256", "")[:16]
        rows.append(
            ft.Container(
                content=ft.Column(
                    [
                        ft.Text(
                            f"{rec.get('filename', '?')}  ({sz_mb:.1f} MiB)  recorded {rec.get('recorded', '')}",
                            size=TYPE["body"]["size"],
                            color=COLORS["text_primary"],
                        ),
                        ft.Text(
                            f"SHA-256: {sha16}...  |  {key}",
                            size=TYPE["caption"]["size"],
                            color=COLORS["text_secondary"],
                        ),
                    ],
                    spacing=2,
                ),
                padding=ft.Padding.symmetric(horizontal=10, vertical=6),
                bgcolor=COLORS["bg"],
                border_radius=SPACING["radius"],
            )
        )
    return rows
