"""Settings screen for the Flet UI (Stage 10).

Exposes appearance (theme + UI scale), update-check toggle, Smart Encryption
Profiles, Argon2id KDF parameters, secure-wipe passes, vault-versioning
settings, the activity-logging toggle, a confirmation-gated Clear All Local
Traces, a Security Health Check, and an About panel.

Flet 0.85.2 notes:
  - The versions-directory chooser uses ft.FilePicker registered as a SERVICE via
    page.services (never the visual overlay), matching the Library screen.
  - Confirmation dialogs use ft.AlertDialog shown via page.show_dialog(dialog) and
    closed via page.pop_dialog(), matching the Re-Key and Activity screens.

All persistence and rebuild logic lives in the Flet-free SettingsController; this
screen only wires controls to it and reflects status.
"""

import flet as ft

from rpm_encrypter.services.controllers.settings_controller import (
    ABOUT_TEXT,
    KDF_IN_PROGRESS_MSG,
    KDF_MEMORY_CHOICES,
    KDF_MEMORY_LABELS,
    KDF_PAR_CHOICES,
    KDF_TIME_CHOICES,
    THEME_CHOICES,
    UI_SCALE_CHOICES,
    VERSION_COUNT_CHOICES,
    VERSION_TOTAL_MB_CHOICES,
    WIPE_PASS_CHOICES,
    SettingsController,
    ensure_modern_settings_defaults,
)
from rpm_encrypter.ui.components import (
    card_panel,
    hint_text,
    register_page_services,
    set_screen_status,
    show_confirm_dialog,
)
from rpm_encrypter.ui.tokens import COLORS, TYPE

PRIVACY_HINT = (
    "Records each operation (action, status, and the file's NAME) to a local "
    "activity log on this device. Off by default; vault contents are never logged."
)
CLEAR_TRACES_HINT = (
    "Erases the activity log, Library cache, saved fingerprints, and recent-file "
    "lists from this device. Vault files are not affected."
)
NO_PROFILES = "No Profiles Saved"
THEME_MODES = {"Dark": ft.ThemeMode.DARK, "Classic": ft.ThemeMode.LIGHT}


class SettingsScreen:
    """Settings screen for the Flet UI."""

    def __init__(self, page: ft.Page, services, shell):
        self.page = page
        self.services = services
        self.shell = shell
        self.controller = SettingsController(services)
        ensure_modern_settings_defaults()
        snap = self.controller.get_snapshot()

        self.theme_dropdown = ft.Dropdown(
            label="Theme",
            value=snap.theme if snap.theme in THEME_CHOICES else "Dark",
            options=[ft.DropdownOption(key=c, text=c) for c in THEME_CHOICES],
            on_select=self._on_theme_change,
            width=160,
        )
        self.scale_dropdown = ft.Dropdown(
            label="UI Scale",
            value=snap.ui_scale if snap.ui_scale in UI_SCALE_CHOICES else "100%",
            options=[ft.DropdownOption(key=c, text=c) for c in UI_SCALE_CHOICES],
            on_select=self._on_scale_change,
            width=130,
        )
        self.updates_checkbox = ft.Checkbox(
            label="Check for updates on startup",
            value=snap.check_updates,
            on_change=self._on_updates_change,
            active_color=COLORS["accent"],
            label_style=ft.TextStyle(size=TYPE["body"]["size"], color=COLORS["text_primary"]),
        )

        self.profile_name_field = ft.TextField(
            label="Profile name",
            value="",
            width=220,
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.profile_dropdown = ft.Dropdown(
            label="Saved profiles",
            options=[],
            width=220,
        )
        self.save_profile_button = ft.Button("Save Current as Profile", on_click=self._save_profile)
        self.delete_profile_button = ft.Button("Delete Selected", on_click=self._delete_profile)
        self.apply_profile_button = ft.Button("Apply Selected", on_click=self._apply_profile)

        self.kdf_memory_dropdown = ft.Dropdown(
            label="Memory (KiB)",
            value=str(snap.argon2_memory),
            options=[
                ft.DropdownOption(key=str(v), text=KDF_MEMORY_LABELS.get(v, str(v)))
                for v in KDF_MEMORY_CHOICES
            ],
            width=200,
        )
        self.kdf_time_dropdown = ft.Dropdown(
            label="Iterations",
            value=str(snap.argon2_time),
            options=[ft.DropdownOption(key=str(v), text=str(v)) for v in KDF_TIME_CHOICES],
            width=140,
        )
        self.kdf_par_dropdown = ft.Dropdown(
            label="Parallelism",
            value=str(snap.argon2_par),
            options=[ft.DropdownOption(key=str(v), text=str(v)) for v in KDF_PAR_CHOICES],
            width=140,
        )
        self.save_kdf_button = ft.Button(
            "Save KDF Settings & Restart Crypto Engine", on_click=self._save_kdf
        )

        self.wipe_dropdown = ft.Dropdown(
            label="Overwrite passes",
            value=str(snap.wipe_passes),
            options=[ft.DropdownOption(key=str(v), text=str(v)) for v in WIPE_PASS_CHOICES],
            on_select=self._on_wipe_change,
            width=140,
        )

        self.versioning_checkbox = ft.Checkbox(
            label="Enable Vault Versioning",
            value=snap.versioning_enabled,
            on_change=self._save_versioning,
            active_color=COLORS["accent"],
            label_style=ft.TextStyle(size=TYPE["body"]["size"], color=COLORS["text_primary"]),
        )
        self.version_count_dropdown = ft.Dropdown(
            label="Max versions per vault",
            value=str(snap.versioning_max_per_vault),
            options=[ft.DropdownOption(key=str(v), text=str(v)) for v in VERSION_COUNT_CHOICES],
            on_select=self._save_versioning,
            width=200,
        )
        self.version_size_dropdown = ft.Dropdown(
            label="Max total size (MiB)",
            value=str(snap.versioning_max_total_mb),
            options=[ft.DropdownOption(key=str(v), text=str(v)) for v in VERSION_TOTAL_MB_CHOICES],
            on_select=self._save_versioning,
            width=200,
        )
        self.version_dir_field = ft.TextField(
            label="Versions directory",
            value=snap.versioning_dir,
            hint_text=self.controller.default_versions_dir(),
            expand=True,
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.version_dir_picker = ft.FilePicker()
        self.browse_version_dir_button = ft.Button("Browse", on_click=self._browse_version_dir)
        self.save_versioning_button = ft.Button(
            "Save Versioning Settings", on_click=self._save_versioning
        )

        self.logging_checkbox = ft.Checkbox(
            label="Enable Activity Logging",
            value=snap.logging_enabled,
            on_change=self._on_logging_change,
            active_color=COLORS["accent"],
            label_style=ft.TextStyle(size=TYPE["body"]["size"], color=COLORS["text_primary"]),
        )
        self.clear_traces_button = ft.Button(
            "Clear All Local Traces", on_click=self._confirm_clear_traces
        )
        self.shell_status_text = ft.Text(
            "",
            size=TYPE["caption"]["size"],
            color=COLORS["text_secondary"],
        )
        self.install_shell_button = ft.Button(
            "Install Context Menu & .vault Association",
            on_click=self._confirm_install_shell_integration,
        )
        self.uninstall_shell_button = ft.Button(
            "Remove Shell Integration",
            on_click=self._uninstall_shell_integration,
        )
        self._refresh_shell_integration_status()
        self.health_button = ft.Button("Run Security Health Check", on_click=self._run_health_check)

    def _on_theme_change(self, _event=None) -> None:
        choice = self.controller.set_theme(self.theme_dropdown.value)
        self.theme_dropdown.value = choice
        if hasattr(self.shell, "apply_theme"):
            self.shell.apply_theme(choice)
        else:
            self.page.theme_mode = THEME_MODES.get(choice, ft.ThemeMode.DARK)
        set_screen_status(self.shell, f"Theme: {choice}")

    def _on_scale_change(self, _event=None) -> None:
        choice = self.controller.set_ui_scale(self.scale_dropdown.value)
        self.scale_dropdown.value = choice
        if hasattr(self.shell, "apply_ui_scale"):
            self.shell.apply_ui_scale(choice)
        set_screen_status(self.shell, f"UI scale: {choice}")

    def _on_updates_change(self, _event=None) -> None:
        enabled = self.controller.set_check_updates(bool(self.updates_checkbox.value))
        self.updates_checkbox.value = enabled
        set_screen_status(
            self.shell,
            "Update check on startup enabled" if enabled else "Update check on startup disabled",
        )

    def _on_logging_change(self, _event=None) -> None:
        enabled = self.controller.set_logging_enabled(bool(self.logging_checkbox.value))
        self.logging_checkbox.value = enabled
        set_screen_status(
            self.shell,
            "Activity logging enabled" if enabled else "Activity logging disabled",
        )

    def _save_kdf(self, _event=None) -> None:
        snap = self.controller.get_snapshot()
        memory = self._dropdown_int(self.kdf_memory_dropdown, snap.argon2_memory)
        time = self._dropdown_int(self.kdf_time_dropdown, snap.argon2_time)
        parallelism = self._dropdown_int(self.kdf_par_dropdown, snap.argon2_par)
        try:
            self.controller.save_kdf_settings(memory, time, parallelism)
        except RuntimeError:
            set_screen_status(self.shell, KDF_IN_PROGRESS_MSG)
            return
        except ValueError as exc:
            self._sync_kdf_from_settings()
            set_screen_status(self.shell, str(exc))
            return
        set_screen_status(self.shell, "Crypto engine reloaded with new KDF parameters")

    def _on_wipe_change(self, _event=None) -> None:
        snap = self.controller.get_snapshot()
        try:
            passes = self.controller.save_wipe_passes(
                self._dropdown_int(self.wipe_dropdown, snap.wipe_passes)
            )
        except ValueError as exc:
            self._sync_kdf_from_settings()
            set_screen_status(self.shell, str(exc))
            return
        set_screen_status(self.shell, f"Wipe passes set to {passes}")

    def _save_versioning(self, _event=None) -> None:
        snap = self.controller.get_snapshot()
        try:
            self.controller.save_versioning_settings(
                enabled=bool(self.versioning_checkbox.value),
                max_per_vault=self._dropdown_int(
                    self.version_count_dropdown, snap.versioning_max_per_vault
                ),
                max_total_mb=self._dropdown_int(
                    self.version_size_dropdown, snap.versioning_max_total_mb
                ),
                versions_dir=self.version_dir_field.value or "",
            )
        except ValueError as exc:
            self._sync_versioning_from_settings()
            set_screen_status(self.shell, str(exc))
            return
        state = "enabled" if self.versioning_checkbox.value else "disabled"
        self._sync_versioning_from_settings()
        set_screen_status(self.shell, f"Versioning {state}")

    async def _browse_version_dir(self, _event=None) -> None:
        register_page_services(self.page, self.version_dir_picker)
        folder = await self.version_dir_picker.get_directory_path()
        if folder:
            self.version_dir_field.value = folder
            self._save_versioning()

    def _refresh_profiles(self) -> None:
        names = self.controller.list_profiles()
        if names:
            self.profile_dropdown.options = [ft.DropdownOption(key=n, text=n) for n in names]
            self.profile_dropdown.value = names[0]
        else:
            self.profile_dropdown.options = [ft.DropdownOption(key=NO_PROFILES, text=NO_PROFILES)]
            self.profile_dropdown.value = NO_PROFILES

    def _save_profile(self, _event=None) -> None:
        try:
            name = self.controller.save_profile(self.profile_name_field.value)
        except ValueError as exc:
            set_screen_status(self.shell, str(exc))
            return
        self.profile_name_field.value = ""
        self._refresh_profiles()
        set_screen_status(self.shell, f"Profile '{name}' saved")

    def _delete_profile(self, _event=None) -> None:
        name = self.profile_dropdown.value
        if not name or name == NO_PROFILES:
            set_screen_status(self.shell, "No profile selected")
            return
        if self.controller.delete_profile(name):
            self._refresh_profiles()
            set_screen_status(self.shell, f"Profile '{name}' deleted")

    def _apply_profile(self, _event=None) -> None:
        name = self.profile_dropdown.value
        if not name or name == NO_PROFILES:
            set_screen_status(self.shell, "No profile selected")
            return
        try:
            applied = self.controller.apply_profile(name)
        except ValueError as exc:
            self._sync_kdf_from_settings()
            set_screen_status(self.shell, str(exc))
            return
        if applied:
            self._sync_kdf_from_settings()
            set_screen_status(self.shell, f"Profile '{name}' applied")

    def _sync_kdf_from_settings(self) -> None:
        snap = self.controller.get_snapshot()
        self.kdf_memory_dropdown.value = str(snap.argon2_memory)
        self.kdf_time_dropdown.value = str(snap.argon2_time)
        self.kdf_par_dropdown.value = str(snap.argon2_par)
        self.wipe_dropdown.value = str(snap.wipe_passes)

    def _sync_versioning_from_settings(self) -> None:
        snap = self.controller.get_snapshot()
        self.versioning_checkbox.value = bool(snap.versioning_enabled)
        self.version_count_dropdown.value = str(snap.versioning_max_per_vault)
        self.version_size_dropdown.value = str(snap.versioning_max_total_mb)
        self.version_dir_field.value = snap.versioning_dir

    def _dropdown_int(self, dropdown, fallback: int) -> int:
        try:
            return int(dropdown.value)
        except (TypeError, ValueError):
            dropdown.value = str(fallback)
            return int(fallback)

    def _run_health_check(self, _event=None) -> None:
        result = self.controller.run_health_check()
        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text(result.title),
            content=ft.Text(result.text),
            actions=[ft.Button("Close", on_click=self._close_dialog)],
        )
        self.page.show_dialog(dialog)
        self.shell.safe_update()

    def _close_dialog(self, _event=None) -> None:
        self.page.pop_dialog()
        self.shell.safe_update()

    def _confirm_clear_traces(self, _event=None) -> None:
        show_confirm_dialog(
            self.page,
            self.shell,
            title="Clear All Local Traces",
            body=(
                "Erase the activity log, Library cache, saved fingerprints, and "
                "recent-file lists from this device? Vault files are not affected."
            ),
            action_label="Clear",
            on_confirm=self._clear_traces_confirmed,
            on_cancel=self._close_dialog,
            pop_on_confirm=False,
        )

    def _clear_traces_confirmed(self, _event=None) -> None:
        result = self.controller.clear_local_traces()
        self.page.pop_dialog()
        if result.errors:
            set_screen_status(
                self.shell,
                "Local traces cleared with errors: " + "; ".join(result.errors),
            )
        else:
            set_screen_status(self.shell, "All local traces cleared")

    def _refresh_shell_integration_status(self) -> None:
        status = self.controller.shell_integration_status()
        if not status.supported:
            self.shell_status_text.value = "Status: Available on Windows only"
            self.install_shell_button.disabled = True
            self.uninstall_shell_button.disabled = True
            return
        self.install_shell_button.disabled = False
        self.uninstall_shell_button.disabled = False
        if status.installed:
            self.shell_status_text.value = (
                "Status: Installed (Explorer context menu & .vault double-click)"
            )
        elif status.context_menu_installed or status.vault_association_installed:
            self.shell_status_text.value = "Status: Partially installed"
        else:
            self.shell_status_text.value = "Status: Not installed"

    def _confirm_install_shell_integration(self, _event=None) -> None:
        show_confirm_dialog(
            self.page,
            self.shell,
            title="Install Windows Shell Integration?",
            body=(
                "Register user-scoped (HKCU\\Software\\Classes) entries for the "
                "Explorer right-click 'Encrypt with RPM Encrypter' action and "
                ".vault double-click association? No administrator rights needed; "
                "you can remove them anytime here."
            ),
            action_label="Install",
            on_confirm=self._install_shell_confirmed,
            on_cancel=self._close_dialog,
            pop_on_confirm=False,
        )

    def _install_shell_confirmed(self, _event=None) -> None:
        self.page.pop_dialog()
        try:
            self.controller.install_shell_integration()
        except Exception as exc:
            set_screen_status(self.shell, f"Shell integration failed: {exc}", is_error=True)
            return
        self._refresh_shell_integration_status()
        set_screen_status(self.shell, "Windows shell integration installed")

    def _uninstall_shell_integration(self, _event=None) -> None:
        try:
            self.controller.uninstall_shell_integration()
        except Exception as exc:
            set_screen_status(self.shell, f"Shell removal failed: {exc}", is_error=True)
            return
        self._refresh_shell_integration_status()
        set_screen_status(self.shell, "Windows shell integration removed")

    def build(self) -> ft.Control:
        register_page_services(self.page, self.version_dir_picker)
        self._refresh_profiles()
        return ft.Container(
            content=ft.Column(
                [
                    ft.Text(
                        "Settings",
                        size=TYPE["page_title"]["size"],
                        weight=ft.FontWeight.W_600,
                        color=COLORS["text_primary"],
                    ),
                    card_panel(
                        "Appearance",
                        [ft.Row([self.theme_dropdown, self.scale_dropdown], spacing=16)],
                        stretch=False,
                    ),
                    card_panel("Updates", [self.updates_checkbox], stretch=False),
                    card_panel(
                        "Smart Encryption Profiles",
                        [
                            ft.Row(
                                [self.profile_name_field, self.save_profile_button],
                                spacing=10,
                            ),
                            ft.Row(
                                [
                                    self.profile_dropdown,
                                    self.apply_profile_button,
                                    self.delete_profile_button,
                                ],
                                spacing=10,
                            ),
                        ],
                        stretch=False,
                    ),
                    card_panel(
                        "Argon2id Key Derivation (applied to new vaults)",
                        [
                            ft.Row(
                                [
                                    self.kdf_memory_dropdown,
                                    self.kdf_time_dropdown,
                                    self.kdf_par_dropdown,
                                ],
                                spacing=16,
                            ),
                            self.save_kdf_button,
                        ],
                        stretch=False,
                    ),
                    card_panel(
                        "Secure Wipe",
                        [
                            ft.Row(
                                [
                                    self.wipe_dropdown,
                                    hint_text("1 pass is sufficient for SSDs; 3+ for HDDs."),
                                ],
                                spacing=16,
                                wrap=True,
                                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            ),
                        ],
                        stretch=False,
                    ),
                    card_panel(
                        "Vault Versioning",
                        [
                            self.versioning_checkbox,
                            ft.Row(
                                [self.version_count_dropdown, self.version_size_dropdown],
                                spacing=16,
                            ),
                            ft.Row(
                                [self.version_dir_field, self.browse_version_dir_button],
                                spacing=10,
                            ),
                            self.save_versioning_button,
                            hint_text(
                                "Versioning is opt-in. Large vaults are fully copied before "
                                "each Re-Key."
                            ),
                        ],
                        stretch=False,
                    ),
                    card_panel(
                        "Privacy & Local Traces",
                        [
                            self.logging_checkbox,
                            hint_text(PRIVACY_HINT),
                            self.clear_traces_button,
                            hint_text(CLEAR_TRACES_HINT),
                        ],
                        stretch=False,
                    ),
                    card_panel(
                        "Windows Shell Integration",
                        [
                            self.shell_status_text,
                            ft.Row(
                                [self.install_shell_button, self.uninstall_shell_button],
                                spacing=10,
                                wrap=True,
                            ),
                            hint_text(
                                "Registers under HKEY_CURRENT_USER only (reversible, no admin rights)."
                            ),
                        ],
                        stretch=False,
                    ),
                    card_panel("Security Health Check", [self.health_button], stretch=False),
                    card_panel("About", [hint_text(ABOUT_TEXT)], stretch=False),
                ],
                spacing=18,
                scroll=ft.ScrollMode.AUTO,
                horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
            ),
            padding=24,
            expand=True,
        )
