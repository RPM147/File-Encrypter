"""Headless command-line interface for RPM Encrypter (100% Flet-free)."""

import argparse
import getpass
import json
import os
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TextIO

from rpm_encrypter.core import (
    MAX_PAYLOAD_SIZE,
    AuthenticationError,
    entropy_to_mnemonic,
    generate_recovery_entropy,
    mnemonic_to_entropy,
)
from rpm_encrypter.services import APP_NAME, APP_VERSION, AppServices, shell_integration
from rpm_encrypter.services.controllers.inspect_controller import InspectController
from rpm_encrypter.storage.atomic import atomic_output


def _unique_path(base: Path) -> Path:
    out, counter = base, 1
    while out.exists():
        out = base.with_name(f"{base.stem}_{counter}{base.suffix}")
        counter += 1
    return out


def _read_secret(
    prompt: str,
    *,
    from_stdin: bool,
    confirm: bool,
    stdin: TextIO,
    getpass_fn: Callable[[str], str],
) -> str:
    if from_stdin:
        raw = stdin.readline()
        secret = raw.rstrip("\r\n")
        if not secret:
            raise ValueError("Empty secret input from stdin.")
        return secret

    secret = getpass_fn(prompt)
    if not secret:
        raise ValueError("Secret input cannot be empty.")
    if confirm:
        second = getpass_fn(f"Confirm {prompt}")
        if secret != second:
            raise ValueError("Entries do not match.")
    return secret


def _format_plain_metadata(metadata: dict) -> str:
    mb = metadata.get("total_size", metadata.get("original_size", 0)) / (1024 * 1024)
    lines = [
        f"Original Name : {metadata.get('filename', 'N/A')}",
        f"Original Size : {metadata.get('original_size', 0):,} bytes ({mb:.2f} MiB)",
        f"File Count    : {metadata.get('file_count', 'N/A')}",
        f"Created       : {metadata.get('created_at', 'N/A')}",
        f"Source Type   : {metadata.get('source_type', 'N/A')}",
        f"KDF           : {metadata.get('kdf_algorithm', 'N/A')} "
        f"(mem={metadata.get('argon_memory', 'N/A')} KiB, "
        f"iters={metadata.get('argon_iterations', 'N/A')}, "
        f"par={metadata.get('argon_parallelism', 'N/A')})",
        f"Cipher        : {metadata.get('encryption', 'N/A')} / "
        f"{metadata.get('payload_encryption', 'N/A')}",
    ]
    files = metadata.get("files", [])
    if files:
        lines.append(f"Manifest ({len(files)} entries):")
        for item in files[:100]:
            lines.append(f"  - {item.get('path', '')} ({item.get('size', 0):,} bytes)")
        if len(files) > 100:
            lines.append(f"  ... and {len(files) - 100} more")
    return "\n".join(lines)


def _wipe_or_unlink(svc: AppServices, path: Path | None) -> None:
    if path is None or not path.exists():
        return
    try:
        svc.wiper.wipe_file(path)
    except Exception:
        path.unlink(missing_ok=True)


def _cmd_encrypt(ns, svc: AppServices, stdin: TextIO, stdout: TextIO, stderr: TextIO, getpass_fn) -> int:
    sources = [Path(s) for s in ns.sources]
    for src in sources:
        if not src.exists():
            print(f"Error: source not found: {src}", file=stderr)
            return 1
    out_dir = Path(ns.output_dir) if ns.output_dir else None
    if out_dir is not None and not out_dir.is_dir():
        print(f"Error: output directory does not exist: {out_dir}", file=stderr)
        return 1

    try:
        password = _read_secret(
            "Vault password: ",
            from_stdin=ns.password_stdin,
            confirm=not ns.password_stdin,
            stdin=stdin,
            getpass_fn=getpass_fn,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=stderr)
        return 1

    recovery_key = generate_recovery_entropy()
    phrase = entropy_to_mnemonic(recovery_key)
    compress = not ns.no_compress

    for src in sources:
        temp_zip: Path | None = None
        try:
            manifest = svc.packager.get_manifest(src)
            total_size = int(manifest.get("total_size", 0) or 0)
            if total_size > MAX_PAYLOAD_SIZE:
                print(
                    f"Error: payload too large (> 32 GiB) for {src.name}: {total_size:,} bytes",
                    file=stderr,
                )
                return 1
            temp_zip = (
                svc.packager.package_folder(src, compress=compress)
                if src.is_dir()
                else svc.packager.package_files([src], compress=compress)
            )
            base_dir = out_dir if out_dir is not None else src.parent
            out_path = _unique_path(base_dir / f"{src.name}.vault")
            atomic_output(
                out_path,
                lambda p, sz=temp_zip, fname=src.name, meta=manifest: svc.crypto.encrypt_file(
                    sz,
                    p,
                    password,
                    original_filename=fname,
                    metadata=meta,
                    recovery_key=recovery_key,
                    target_container_mb=ns.container_mb,
                ),
            )
            if ns.wipe:
                if src.is_dir():
                    svc.wiper.wipe_folder(src)
                else:
                    svc.wiper.wipe_file(src)
            print(f"Encrypted: {out_path}", file=stdout)
        except Exception as exc:
            print(f"Error encrypting {src.name}: {exc}", file=stderr)
            return 1
        finally:
            _wipe_or_unlink(svc, temp_zip)

    if ns.recovery_out:
        rec_path = Path(ns.recovery_out)
        rec_path.parent.mkdir(parents=True, exist_ok=True)
        rec_path.write_text(phrase + "\n", encoding="utf-8")
        try:
            os.chmod(rec_path, 0o600)
        except OSError:
            pass
        print(f"Recovery phrase written to: {rec_path}", file=stdout)
    else:
        print("\nIMPORTANT - Save this 24-word recovery phrase securely:", file=stdout)
        print(f"  {phrase}", file=stdout)
    return 0


def _resolve_decrypt_auth(ns, stdin: TextIO, getpass_fn) -> tuple[str | None, bytes | None]:
    if ns.recovery or ns.recovery_stdin:
        phrase = _read_secret(
            "24-word recovery phrase: ",
            from_stdin=ns.recovery_stdin,
            confirm=False,
            stdin=stdin,
            getpass_fn=getpass_fn,
        )
        return None, mnemonic_to_entropy(phrase)
    password = _read_secret(
        "Vault password: ",
        from_stdin=ns.password_stdin,
        confirm=False,
        stdin=stdin,
        getpass_fn=getpass_fn,
    )
    return password, None


def _cmd_decrypt(ns, svc: AppServices, stdin: TextIO, stdout: TextIO, stderr: TextIO, getpass_fn) -> int:
    vaults = [Path(v) for v in ns.vaults]
    for v in vaults:
        if not v.is_file():
            print(f"Error: vault file not found: {v}", file=stderr)
            return 1
        if v.suffix.lower() != ".vault":
            print(f"Error: only .vault files can be decrypted: {v.name}", file=stderr)
            return 1

    out_dir = Path(ns.output_dir) if ns.output_dir else None
    if out_dir is not None and not out_dir.is_dir():
        print(f"Error: output directory does not exist: {out_dir}", file=stderr)
        return 1

    try:
        password, recovery_key = _resolve_decrypt_auth(ns, stdin, getpass_fn)
    except ValueError as exc:
        print(f"Error: {exc}", file=stderr)
        return 1

    for vault in vaults:
        temp_zip: Path | None = None
        extract_dir: Path | None = None
        try:
            fd, temp_name = tempfile.mkstemp(prefix=".rpm_pack_", suffix=".zip")
            os.close(fd)
            temp_zip = Path(temp_name)
            header = svc.crypto.decrypt_file(
                vault,
                temp_zip,
                password,
                recovery_key=recovery_key,
            )
            target_root = out_dir if out_dir is not None else vault.parent
            orig_name = header.payload.filename
            stem = Path(orig_name).stem if Path(orig_name).suffix else orig_name
            extract_dir = _unique_path(target_root / stem)
            svc.packager.extract_archive(temp_zip, extract_dir)
            print(f"Decrypted: {vault.name} -> {extract_dir}", file=stdout)
        except AuthenticationError:
            if extract_dir is not None and extract_dir.exists():
                svc.wiper.wipe_folder(extract_dir)
            print(f"Authentication failed for {vault.name}.", file=stderr)
            return 2
        except Exception as exc:
            if extract_dir is not None and extract_dir.exists():
                svc.wiper.wipe_folder(extract_dir)
            print(f"Error decrypting {vault.name}: {exc}", file=stderr)
            return 1
        finally:
            _wipe_or_unlink(svc, temp_zip)
    return 0


def _cmd_inspect(ns, svc: AppServices, stdin: TextIO, stdout: TextIO, stderr: TextIO, getpass_fn) -> int:
    vault = Path(ns.vault)
    if not vault.is_file():
        print(f"Error: vault file not found: {vault}", file=stderr)
        return 1

    if ns.integrity_only:
        ok, msg, sha = InspectController._check_vault_integrity(vault)
        if ns.json:
            print(
                json.dumps(
                    {"path": str(vault), "ok": ok, "sha256": sha, "message": msg},
                    indent=2,
                ),
                file=stdout,
            )
        else:
            print(msg, file=stdout)
        return 0 if ok else 1

    try:
        password, recovery_key = _resolve_decrypt_auth(ns, stdin, getpass_fn)
    except ValueError as exc:
        print(f"Error: {exc}", file=stderr)
        return 1

    try:
        metadata = svc.inspector.inspect(vault, password=password, recovery_key=recovery_key)
    except AuthenticationError:
        print(f"Authentication failed for {vault.name}.", file=stderr)
        return 2
    except Exception as exc:
        print(f"Error inspecting {vault.name}: {exc}", file=stderr)
        return 1

    if ns.json:
        print(json.dumps({"path": str(vault), "metadata": metadata}, indent=2), file=stdout)
    else:
        print(_format_plain_metadata(metadata), file=stdout)
    return 0


def _cmd_rekey(ns, svc: AppServices, stdin: TextIO, stdout: TextIO, stderr: TextIO, getpass_fn) -> int:
    vault = Path(ns.vault)
    if not vault.is_file():
        print(f"Error: vault file not found: {vault}", file=stderr)
        return 1

    try:
        old_pw = _read_secret(
            "Current password: ",
            from_stdin=ns.password_stdin,
            confirm=False,
            stdin=stdin,
            getpass_fn=getpass_fn,
        )
        new_pw = _read_secret(
            "New password: ",
            from_stdin=ns.password_stdin,
            confirm=not ns.password_stdin,
            stdin=stdin,
            getpass_fn=getpass_fn,
        )
        if new_pw == old_pw:
            raise ValueError("New password must differ from the current password.")
    except ValueError as exc:
        print(f"Error: {exc}", file=stderr)
        return 1

    tmp = vault.with_suffix(".rekey.tmp")
    try:
        if svc.versioner.enabled:
            svc.versioner.save_version(vault)
        svc.crypto.rekey_vault(vault, tmp, old_pw, new_pw)
        tmp.replace(vault)
        print(f"Re-keyed: {vault}", file=stdout)
        return 0
    except AuthenticationError:
        print(f"Authentication failed for {vault.name}.", file=stderr)
        return 2
    except Exception as exc:
        print(f"Error re-keying {vault.name}: {exc}", file=stderr)
        return 1
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def _cmd_shell_integration(ns, stdout: TextIO, stderr: TextIO) -> int:
    try:
        if ns.action == "status":
            st = shell_integration.get_status()
        elif ns.action == "install":
            st = shell_integration.install_shell_integration()
        else:
            st = shell_integration.uninstall_shell_integration()
    except shell_integration.ShellIntegrationError as exc:
        print(f"Error: {exc}", file=stderr)
        return 1

    print(
        f"supported={st.supported} installed={st.installed} "
        f"context_menu={st.context_menu_installed} "
        f"vault_association={st.vault_association_installed}",
        file=stdout,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI ArgumentParser (never accepts passwords as flags)."""
    parser = argparse.ArgumentParser(
        prog="rpm-encrypter",
        description=f"{APP_NAME} command-line interface (Vault Format v4).",
    )
    parser.add_argument("--version", action="store_true", help="Show version and exit.")
    sub = parser.add_subparsers(dest="cmd")

    enc = sub.add_parser("encrypt", help="Encrypt files or folders into .vault archives.")
    enc.add_argument("sources", nargs="+", help="Files or directories to encrypt.")
    enc.add_argument("-o", "--output-dir", help="Destination directory (default: next to source).")
    enc.add_argument("--container-mb", type=int, default=0, help="Target container size in MiB.")
    enc.add_argument("--no-compress", action="store_true", help="Disable ZIP compression.")
    enc.add_argument("--wipe", action="store_true", help="Securely wipe original inputs after encrypt.")
    enc.add_argument("--recovery-out", help="Write the 24-word recovery phrase to a file.")
    enc.add_argument("--password-stdin", action="store_true", help="Read password line from stdin.")

    dec = sub.add_parser("decrypt", help="Decrypt .vault archives.")
    dec.add_argument("vaults", nargs="+", help=".vault files to decrypt.")
    dec.add_argument("-o", "--output-dir", help="Destination directory (default: next to vault).")
    dec_auth = dec.add_mutually_exclusive_group()
    dec_auth.add_argument("--password-stdin", action="store_true", help="Read password line from stdin.")
    dec_auth.add_argument("--recovery", action="store_true", help="Prompt for 24-word recovery phrase.")
    dec_auth.add_argument("--recovery-stdin", action="store_true", help="Read recovery phrase from stdin.")

    ins = sub.add_parser("inspect", help="Inspect vault integrity or encrypted metadata.")
    ins.add_argument("vault", help=".vault file to inspect.")
    ins.add_argument("--json", action="store_true", help="Output JSON.")
    ins_auth = ins.add_mutually_exclusive_group()
    ins_auth.add_argument(
        "--integrity-only",
        action="store_true",
        help="Check header structure and SHA-256 without a password.",
    )
    ins_auth.add_argument("--password-stdin", action="store_true", help="Read password line from stdin.")
    ins_auth.add_argument("--recovery", action="store_true", help="Prompt for 24-word recovery phrase.")
    ins_auth.add_argument("--recovery-stdin", action="store_true", help="Read recovery phrase from stdin.")

    rk = sub.add_parser("rekey", help="Rotate the vault password without decrypting payload.")
    rk.add_argument("vault", help=".vault file to re-key.")
    rk.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read current password (line 1) and new password (line 2) from stdin.",
    )

    sh = sub.add_parser("shell-integration", help="Manage Windows Explorer integration (HKCU).")
    sh.add_argument("action", choices=["status", "install", "uninstall"])
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    services: AppServices | None = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    getpass_fn: Callable[[str], str] | None = None,
) -> int:
    """Execute the headless CLI and return an integer process exit code."""
    in_stream = stdin if stdin is not None else sys.stdin
    out_stream = stdout if stdout is not None else sys.stdout
    err_stream = stderr if stderr is not None else sys.stderr
    gp = getpass_fn if getpass_fn is not None else getpass.getpass

    parser = build_parser()
    ns = parser.parse_args(list(argv) if argv is not None else None)
    if ns.version:
        print(f"{APP_NAME} {APP_VERSION}", file=out_stream)
        return 0
    if not ns.cmd:
        parser.print_help(out_stream)
        return 0
    if ns.cmd == "shell-integration":
        return _cmd_shell_integration(ns, out_stream, err_stream)

    svc = services if services is not None else AppServices()
    if ns.cmd == "encrypt":
        return _cmd_encrypt(ns, svc, in_stream, out_stream, err_stream, gp)
    if ns.cmd == "decrypt":
        return _cmd_decrypt(ns, svc, in_stream, out_stream, err_stream, gp)
    if ns.cmd == "inspect":
        return _cmd_inspect(ns, svc, in_stream, out_stream, err_stream, gp)
    if ns.cmd == "rekey":
        return _cmd_rekey(ns, svc, in_stream, out_stream, err_stream, gp)
    parser.print_help(err_stream)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
