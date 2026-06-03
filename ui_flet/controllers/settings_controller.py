"""Settings controller for the Flet UI (Stage 10).

Owns every Settings-screen behavior that does not require a display: reading the
current settings snapshot, persisting appearance / update / logging toggles,
saving Argon2id KDF parameters (and rebuilding the crypto engine), secure-wipe
passes, vault-versioning settings (and rebuilding the versioner), Smart
Encryption Profiles (save / delete / apply), the Security Health Check, and the
confirmation-gated Clear All Local Traces.

It imports NO Flet symbols so it is unit-testable without a display. The persisted
config and backend services are owned by the frozen backend; this controller only
talks to app_config, vault_scanner, versioning, the crypto/wiper services, and the
SecureWiper constructor.
"""
import platform
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import app_config
import vault_scanner
import versioning
from app_constants import APP_NAME, APP_VERSION
from crypto_core import ARGON2_MEMORY_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM
from file_handler import SecureWiper


# --- selector choices ---------------------------------------------------------
THEME_CHOICES = ["Dark", "Classic"]
UI_SCALE_CHOICES = ["80%", "90%", "100%", "110%", "120%"]

KDF_MEMORY_CHOICES = [16384, 32768, 65536, 131072, 262144, 524288]
KDF_MEMORY_LABELS = {
    16384: "16 MiB",
    32768: "32 MiB",
    65536: "64 MiB (default)",
    131072: "128 MiB",
    262144: "256 MiB",
    524288: "512 MiB",
}
KDF_TIME_CHOICES = [1, 2, 3, 4, 5, 6, 8, 10]
KDF_PAR_CHOICES = [1, 2, 4, 8, 16]

WIPE_PASS_CHOICES = [1, 3, 7]

VERSION_COUNT_CHOICES = [1, 2, 3, 5, 10, 20]
VERSION_TOTAL_MB_CHOICES = [256, 512, 1024, 2048, 4096, 8192]

RESERVED_PROFILE_NAMES = {"custom", "no profiles saved"}

KDF_IN_PROGRESS_MSG = "Cannot change KDF settings while an operation is in progress"

DEFAULT_VERSION_COUNT = 5
DEFAULT_VERSION_TOTAL_MB = 2048

MODERN_SSD_DEFAULT_SETTINGS = {
    "theme": "Dark",
    "ui_scale": "100%",
    "check_updates": False,
    "argon2_memory": ARGON2_MEMORY_COST,
    "argon2_time": ARGON2_TIME_COST,
    "argon2_par": ARGON2_PARALLELISM,
    "wipe_passes": 1,
    "versioning_enabled": False,
    "versioning_max_per_vault": DEFAULT_VERSION_COUNT,
    "versioning_max_total_mb": DEFAULT_VERSION_TOTAL_MB,
    "versioning_dir": "",
    "logging_enabled": False,
}

ABOUT_TEXT = (
    f"{APP_NAME}  v{APP_VERSION}\n"
    "Envelope Encryption: AES-256-GCM  -  Argon2id KDF\n"
    "\n"
    "Local-only desktop encryptor. Vault contents never leave this device."
)


# --- result/value dataclasses -------------------------------------------------
@dataclass(frozen=True)
class SettingsSnapshot:
    theme: str
    ui_scale: str
    check_updates: bool
    argon2_memory: int
    argon2_time: int
    argon2_par: int
    wipe_passes: int
    versioning_enabled: bool
    versioning_max_per_vault: int
    versioning_max_total_mb: int
    versioning_dir: str
    logging_enabled: bool


@dataclass(frozen=True)
class HealthCheckResult:
    title: str
    issues: list
    passes: list
    text: str


@dataclass(frozen=True)
class ClearTracesResult:
    errors: list = field(default_factory=list)


def _coerce_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return bool(default)
    if isinstance(value, str):
        raw = value.strip().lower()
        if raw in ("1", "true", "yes", "on"):
            return True
        if raw in ("0", "false", "no", "off", ""):
            return False
    return bool(value)


def _choice_or_default(value: Any, choices: list, default: Any):
    return value if value in choices else default


def _int_choice_or_default(value: Any, choices: list[int], default: int) -> int:
    normalized = _coerce_int(value, default)
    return normalized if normalized in choices else int(default)


def _require_choice(value: Any, choices: list, label: str) -> int:
    """Validate a security-bearing integer setting against its allowed choices.

    Raises ValueError (never clamps) so callers cannot silently persist
    out-of-policy values. Returns the normalized int on success.
    """
    try:
        normalized = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"Invalid {label}") from None
    if normalized not in choices:
        allowed = ", ".join(str(v) for v in choices)
        raise ValueError(f"Invalid {label}; allowed values: {allowed}")
    return normalized


def normalize_settings(settings: dict | None) -> dict:
    """Return UI-safe persisted settings for a modern SSD desktop default."""
    settings = settings or {}
    return {
        "theme": _choice_or_default(
            str(settings.get("theme", MODERN_SSD_DEFAULT_SETTINGS["theme"]) or ""),
            THEME_CHOICES,
            MODERN_SSD_DEFAULT_SETTINGS["theme"],
        ),
        "ui_scale": _choice_or_default(
            str(settings.get("ui_scale", MODERN_SSD_DEFAULT_SETTINGS["ui_scale"]) or ""),
            UI_SCALE_CHOICES,
            MODERN_SSD_DEFAULT_SETTINGS["ui_scale"],
        ),
        "check_updates": _coerce_bool(
            settings.get("check_updates", MODERN_SSD_DEFAULT_SETTINGS["check_updates"]),
            MODERN_SSD_DEFAULT_SETTINGS["check_updates"],
        ),
        "argon2_memory": _int_choice_or_default(
            settings.get("argon2_memory", ARGON2_MEMORY_COST),
            KDF_MEMORY_CHOICES,
            ARGON2_MEMORY_COST,
        ),
        "argon2_time": _int_choice_or_default(
            settings.get("argon2_time", ARGON2_TIME_COST),
            KDF_TIME_CHOICES,
            ARGON2_TIME_COST,
        ),
        "argon2_par": _int_choice_or_default(
            settings.get("argon2_par", ARGON2_PARALLELISM),
            KDF_PAR_CHOICES,
            ARGON2_PARALLELISM,
        ),
        "wipe_passes": _int_choice_or_default(
            settings.get("wipe_passes", MODERN_SSD_DEFAULT_SETTINGS["wipe_passes"]),
            WIPE_PASS_CHOICES,
            MODERN_SSD_DEFAULT_SETTINGS["wipe_passes"],
        ),
        "versioning_enabled": _coerce_bool(
            settings.get("versioning_enabled", MODERN_SSD_DEFAULT_SETTINGS["versioning_enabled"]),
            MODERN_SSD_DEFAULT_SETTINGS["versioning_enabled"],
        ),
        "versioning_max_per_vault": _int_choice_or_default(
            settings.get("versioning_max_per_vault", DEFAULT_VERSION_COUNT),
            VERSION_COUNT_CHOICES,
            DEFAULT_VERSION_COUNT,
        ),
        "versioning_max_total_mb": _int_choice_or_default(
            settings.get("versioning_max_total_mb", DEFAULT_VERSION_TOTAL_MB),
            VERSION_TOTAL_MB_CHOICES,
            DEFAULT_VERSION_TOTAL_MB,
        ),
        "versioning_dir": str(
            settings.get("versioning_dir", MODERN_SSD_DEFAULT_SETTINGS["versioning_dir"]) or ""
        ).strip(),
        "logging_enabled": _coerce_bool(
            settings.get("logging_enabled", MODERN_SSD_DEFAULT_SETTINGS["logging_enabled"]),
            MODERN_SSD_DEFAULT_SETTINGS["logging_enabled"],
        ),
    }


def ensure_modern_settings_defaults() -> None:
    """Persist missing/invalid settings so Flet dropdowns never render blank."""
    def _normalize(cfg: dict) -> None:
        cfg["settings"] = normalize_settings(cfg.get("settings", {}))

    app_config._mutate_cfg(_normalize)


def _validated_profile_values(profile: dict) -> dict:
    return {
        "argon2_memory": _require_choice(
            profile.get("argon2_memory", ARGON2_MEMORY_COST),
            KDF_MEMORY_CHOICES,
            "Argon2 memory",
        ),
        "argon2_time": _require_choice(
            profile.get("argon2_time", ARGON2_TIME_COST),
            KDF_TIME_CHOICES,
            "Argon2 iterations",
        ),
        "argon2_par": _require_choice(
            profile.get("argon2_par", ARGON2_PARALLELISM),
            KDF_PAR_CHOICES,
            "Argon2 parallelism",
        ),
        "wipe_passes": _require_choice(
            profile.get("wipe_passes", 1),
            WIPE_PASS_CHOICES,
            "wipe passes",
        ),
    }


class SettingsController:
    """Reads and manages persisted settings + profiles.
    FLET-FREE -> unit-testable without a display."""

    def __init__(self, services):
        self.services = services

    # --- snapshot -------------------------------------------------------------
    def get_snapshot(self) -> SettingsSnapshot:
        settings = normalize_settings(app_config._load_cfg().get("settings", {}))
        return SettingsSnapshot(
            theme=settings["theme"],
            ui_scale=settings["ui_scale"],
            check_updates=settings["check_updates"],
            argon2_memory=settings["argon2_memory"],
            argon2_time=settings["argon2_time"],
            argon2_par=settings["argon2_par"],
            wipe_passes=settings["wipe_passes"],
            versioning_enabled=settings["versioning_enabled"],
            versioning_max_per_vault=settings["versioning_max_per_vault"],
            versioning_max_total_mb=settings["versioning_max_total_mb"],
            versioning_dir=settings["versioning_dir"],
            logging_enabled=settings["logging_enabled"],
        )

    # --- simple toggles -------------------------------------------------------
    def set_theme(self, choice: str) -> str:
        choice = choice if choice in THEME_CHOICES else "Dark"
        app_config.save_setting("theme", choice)
        return choice

    def set_ui_scale(self, choice: str) -> str:
        choice = choice if choice in UI_SCALE_CHOICES else "100%"
        app_config.save_setting("ui_scale", choice)
        return choice

    def set_check_updates(self, enabled: bool) -> bool:
        enabled = bool(enabled)
        app_config.save_setting("check_updates", enabled)
        return enabled

    def set_logging_enabled(self, enabled: bool) -> bool:
        enabled = bool(enabled)
        app_config.save_setting("logging_enabled", enabled)
        logger = getattr(self.services, "activity_logger", None)
        if logger is not None and hasattr(logger, "enabled"):
            logger.enabled = enabled
        return enabled

    # --- KDF ------------------------------------------------------------------
    def save_kdf_settings(self, memory: int, time: int, parallelism: int) -> None:
        if getattr(self.services, "is_processing", False):
            raise RuntimeError(KDF_IN_PROGRESS_MSG)
        memory = _require_choice(memory, KDF_MEMORY_CHOICES, "Argon2 memory")
        time = _require_choice(time, KDF_TIME_CHOICES, "Argon2 iterations")
        parallelism = _require_choice(parallelism, KDF_PAR_CHOICES, "Argon2 parallelism")
        app_config.save_setting("argon2_memory", memory)
        app_config.save_setting("argon2_time", time)
        app_config.save_setting("argon2_par", parallelism)
        self.services.rebuild_crypto()

    # --- secure wipe ----------------------------------------------------------
    def save_wipe_passes(self, passes: int) -> int:
        passes = _require_choice(passes, WIPE_PASS_CHOICES, "wipe passes")
        app_config.save_setting("wipe_passes", passes)
        self.services.wiper = SecureWiper(passes=passes)
        return passes

    # --- versioning -----------------------------------------------------------
    def save_versioning_settings(
        self, enabled: bool, max_per_vault: int, max_total_mb: int, versions_dir: str
    ) -> None:
        enabled = bool(enabled)
        if enabled:
            max_per_vault = _require_choice(
                max_per_vault, VERSION_COUNT_CHOICES, "max versions per vault")
            max_total_mb = _require_choice(
                max_total_mb, VERSION_TOTAL_MB_CHOICES, "max total size MiB")
        else:
            max_per_vault = _int_choice_or_default(
                max_per_vault, VERSION_COUNT_CHOICES, DEFAULT_VERSION_COUNT)
            max_total_mb = _int_choice_or_default(
                max_total_mb, VERSION_TOTAL_MB_CHOICES, DEFAULT_VERSION_TOTAL_MB)
        versions_dir = str(versions_dir or "").strip()
        app_config.save_setting("versioning_enabled", enabled)
        app_config.save_setting("versioning_max_per_vault", max_per_vault)
        app_config.save_setting("versioning_max_total_mb", max_total_mb)
        app_config.save_setting("versioning_dir", versions_dir)
        self.services.versioner = self.services._build_versioner()

    def default_versions_dir(self) -> str:
        return str(versioning.VERSIONS_ROOT_DEFAULT)

    # --- profiles -------------------------------------------------------------
    def list_profiles(self) -> list:
        return list(app_config._load_cfg().get("profiles", {}).keys())

    def save_profile(self, name: str) -> str:
        name = (name or "").strip()
        if not name:
            raise ValueError("Profile name is required")
        if name.lower() in RESERVED_PROFILE_NAMES:
            raise ValueError("That profile name is reserved")

        def _save(cfg: dict) -> None:
            profiles = cfg.setdefault("profiles", {})
            settings = cfg.get("settings", {})
            profiles[name] = _validated_profile_values(settings)
        app_config._mutate_cfg(_save)
        return name

    def delete_profile(self, name: str) -> bool:
        deleted = {"ok": False}

        def _delete(cfg: dict) -> None:
            profiles = cfg.get("profiles", {})
            if name in profiles:
                del profiles[name]
                deleted["ok"] = True
        app_config._mutate_cfg(_delete)
        return deleted["ok"]

    def apply_profile(self, name: str) -> bool:
        if name in ("Custom", "No Profiles Saved"):
            return False
        profile = app_config._load_cfg().get("profiles", {}).get(name)
        if not profile:
            return False
        values = _validated_profile_values(profile)
        app_config.save_setting("argon2_memory", values["argon2_memory"])
        app_config.save_setting("argon2_time", values["argon2_time"])
        app_config.save_setting("argon2_par", values["argon2_par"])
        wipe = values["wipe_passes"]
        app_config.save_setting("wipe_passes", wipe)
        self.services.rebuild_crypto()
        self.services.wiper = SecureWiper(passes=wipe)
        return True

    # --- health check ---------------------------------------------------------
    def run_health_check(self) -> HealthCheckResult:
        settings = app_config._load_cfg().get("settings", {})
        mem = _coerce_int(settings.get("argon2_memory", ARGON2_MEMORY_COST), ARGON2_MEMORY_COST)
        iters = _coerce_int(settings.get("argon2_time", ARGON2_TIME_COST), ARGON2_TIME_COST)
        wipe = _coerce_int(settings.get("wipe_passes", 1), 1)

        issues: list = []
        passes: list = []

        if mem >= 65536 and iters >= 3:
            passes.append("[OK] Argon2id parameters meet or exceed OWASP baselines.")
        else:
            issues.append(
                "[!] Argon2id parameters are below OWASP baselines "
                "(recommend >= 64 MiB memory, >= 3 iterations).")

        if wipe >= 1:
            passes.append("[OK] Secure Wipe is configured (passes >= 1).")
        else:
            issues.append(
                "[!] Secure Wipe passes is 0. Original files will not be securely deleted.")

        if self._detect_ssd():
            passes.append("[i] SSD detected. 1 wipe pass is sufficient due to wear-leveling.")
        else:
            passes.append(
                "[i] Storage medium: assuming HDD or indeterminate. "
                "3+ wipe passes recommended for HDDs.")

        text = "SECURITY HEALTH CHECK RESULTS\n\n"
        if issues:
            text += "Needs Attention:\n" + "\n".join(issues) + "\n\n"
        text += "Good:\n" + "\n".join(passes)

        return HealthCheckResult(
            title="Security Health Check",
            issues=issues,
            passes=passes,
            text=text,
        )

    def _detect_ssd(self) -> bool:
        try:
            if platform.system() == "Windows":
                res = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     "Get-PhysicalDisk | Select-Object -ExpandProperty MediaType"],
                    capture_output=True, text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW, timeout=8)
                return "SSD" in res.stdout
            if platform.system() == "Linux":
                for p in Path("/sys/block").glob("*/queue/rotational"):
                    if p.read_text().strip() == "0":
                        return True
        except Exception:
            pass
        return False

    # --- clear local traces ---------------------------------------------------
    def clear_local_traces(self) -> ClearTracesResult:
        errors: list = []

        logger = getattr(self.services, "activity_logger", None)
        if logger is not None:
            try:
                logger.clear_logs()
            except Exception as exc:
                errors.append(f"activity log: {exc}")

        try:
            vault_scanner.CACHE_FILE.unlink(missing_ok=True)
        except Exception as exc:
            errors.append(f"library cache: {exc}")

        scanner = getattr(self.services, "scanner", None)
        if scanner is not None:
            try:
                scanner.cache = {}
            except Exception:
                pass

        try:
            def _clear(cfg: dict) -> None:
                cfg["fingerprints"] = {}
                cfg["enc_sources"] = []
                cfg["dec_sources"] = []
                cfg["rekey_vaults"] = []
            app_config._mutate_cfg(_clear)
        except Exception as exc:
            errors.append(f"config: {exc}")

        return ClearTracesResult(errors=errors)
