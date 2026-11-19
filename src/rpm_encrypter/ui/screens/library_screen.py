"""Vault Library screen for the Flet UI (Stage 5).

Manage monitored directories -> scan them with VaultScanner on a worker thread ->
render the (unauthenticated) `.vault` results -> search/filter the rendered rows.

The Library is deliberately NON-sensitive: no password fields, no decrypt, no
metadata unlock. The scan output is read WITHOUT authentication and may be
spoofed, so the screen carries a permanent warning and never presents the rows as
authenticated truth.
"""
from pathlib import Path

import flet as ft

from rpm_encrypter.services.controllers.library_controller import LibraryController
from rpm_encrypter.services.events import LibraryResultsEvent
from rpm_encrypter.ui.components import (
    card_panel,
    empty_text,
    finish_screen_operation,
    register_page_services,
    set_screen_status,
    source_row,
)
from rpm_encrypter.ui.tokens import COLORS, TYPE, SPACING


_WARNING = "Vault metadata is read without authentication and may be spoofed."


class LibraryScreen:
    """Manage monitored directories and render unauthenticated scan results."""

    def __init__(self, page: ft.Page, services, shell):
        self.page = page
        self.services = services
        self.shell = shell
        self.last_results = []
        self._auto_scan_started = False

        self.directory_picker = ft.FilePicker()

        self.dir_list = ft.Column(spacing=6, scroll=ft.ScrollMode.AUTO)
        self.results_list = ft.Column(spacing=6, scroll=ft.ScrollMode.AUTO)
        self.search_field = ft.TextField(
            hint_text="Search vaults...",
            on_change=self._on_search_change,
            expand=True,
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.add_button = ft.Button(
            "Add Directory", on_click=lambda _e: self.page.run_task(self._pick_directory)
        )
        self.scan_button = ft.Button("Scan Now", on_click=self._scan_library)
        self.clear_search_button = ft.Button("Clear", on_click=self._clear_search)

    # --- monitored directories ---
    def _refresh_dirs(self) -> None:
        dirs = LibraryController.load_dirs()
        if not dirs:
            self.dir_list.controls = [
                empty_text("No directories monitored. Add a directory to start.")
            ]
            return
        self.dir_list.controls = [
            source_row(d, lambda _e, value=d: self._remove_dir(value)) for d in dirs
        ]

    def _remove_dir(self, path: str) -> None:
        # Removes the directory from config ONLY. Never deletes folders, vault
        # files, or cache from disk.
        removed = LibraryController.remove_dir(path)
        self._refresh_dirs()
        if not LibraryController.load_dirs():
            self.last_results = []
            self._render_results()
            self.shell.status_text.value = "No directories monitored"
            self.shell.safe_update()
            return

        self.shell.status_text.value = (
            "Directory removed" if removed else "Directory was not monitored"
        )
        self.shell.safe_update()

    async def _pick_directory(self):
        try:
            folder = await self.directory_picker.get_directory_path()
            if not folder:
                return
            if not Path(folder).is_dir():
                set_screen_status(self.shell, "Selected path is not a directory")
                return
            added = LibraryController.add_dir(folder)
            self._refresh_dirs()
            if added:
                self.shell.status_text.value = "Directory added"
                self.shell.safe_update()
                self._scan_library()
            else:
                set_screen_status(self.shell, "Directory already monitored")
        except Exception as exc:
            set_screen_status(self.shell, f"Directory picker failed: {exc}")

    # --- scanning ---
    def _scan_library(self, _event=None):
        if self.services.is_processing:
            return
        dirs = LibraryController.load_dirs()
        if not dirs:
            self.last_results = []
            self._render_results()
            self.shell.status_text.value = "No directories monitored"
            self.shell.safe_update()
            return
        self.services.is_processing = True
        self.services.cancel_requested = False
        self.shell.set_busy(self.scan_button)
        self.results_list.controls = [empty_text("Scanning directories...")]
        self.shell.safe_update()
        LibraryController(self.services).start_scan(dirs)

    def _maybe_auto_scan(self) -> None:
        if self._auto_scan_started:
            return
        if LibraryController.load_dirs():
            self._auto_scan_started = True
            self._scan_library()

    # --- search ---
    def _clear_search(self, _event=None):
        self.search_field.value = ""
        self._render_results()
        self.shell.safe_update()

    def _on_search_change(self, _event=None):
        self._render_results()
        self.shell.safe_update()

    # --- result handler (called by AppShell on the poll loop) ---
    def on_library_results(self, event: LibraryResultsEvent):
        error = event.error
        if error:
            self.last_results = []
            self._render_results()
            finish_screen_operation(self.services, self.shell, error)
            return
        self.last_results = self._filter_current_dir_results(event.data)
        self._render_results()
        finish_screen_operation(
            self.services,
            self.shell,
            f"Library scan complete. Found {len(self.last_results)} vaults.",
        )

    # --- rendering ---
    def _filter_current_dir_results(self, results):
        current_dirs = []
        for d in LibraryController.load_dirs():
            try:
                current_dirs.append(Path(d).resolve())
            except (OSError, RuntimeError):
                pass
        if not current_dirs:
            return []

        filtered = []
        for row in results:
            try:
                path = Path(str(row.get("path", ""))).resolve()
            except (OSError, RuntimeError):
                continue
            if any(path == root or path.is_relative_to(root) for root in current_dirs):
                filtered.append(row)
        return filtered

    def _filtered_results(self):
        query = (self.search_field.value or "").strip().lower()
        if not query:
            return self.last_results
        out = []
        for r in self.last_results:
            haystack = " ".join(
                [
                    str(r.get("filename", "")),
                    str(r.get("path", "")),
                    str(r.get("source_type", "")),
                ]
            ).lower()
            if query in haystack:
                out.append(r)
        return out

    def _render_results(self) -> None:
        if not LibraryController.load_dirs():
            self.results_list.controls = [
                empty_text("No directories monitored. Add a directory to start.")
            ]
            return
        query = (self.search_field.value or "").strip()
        if not self.last_results and not query:
            self.results_list.controls = [empty_text("No .vault files found.")]
            return
        filtered = self._filtered_results()
        if not filtered:
            self.results_list.controls = [
                empty_text("No .vault files found matching the search.")
            ]
            return

        rows = sorted(
            filtered,
            key=lambda r: (str(r.get("created_at", "")), str(r.get("path", ""))),
            reverse=True,
        )
        self.results_list.controls = [self._result_row(r) for r in rows]

    def _result_row(self, r) -> ft.Control:
        filename = str(r.get("filename", "Unknown"))
        container = self._format_size(r.get("container_size", 0))
        encrypted = self._format_size(r.get("encrypted_size", 0))
        stype = str(r.get("source_type", "Unknown"))
        created = str(r.get("created_at", "Unknown"))
        path = str(r.get("path", ""))
        return ft.Container(
            content=ft.Column(
                [
                    ft.Text(
                        filename,
                        size=TYPE["body"]["size"],
                        weight=ft.FontWeight.W_600,
                        color=COLORS["text_primary"],
                    ),
                    ft.Text(
                        f"Container: {container}  |  Encrypted: {encrypted}  |  {stype}  |  {created}",
                        size=TYPE["caption"]["size"],
                        color=COLORS["text_secondary"],
                    ),
                    ft.Text(path, size=TYPE["caption"]["size"], color=COLORS["text_secondary"]),
                ],
                spacing=2,
            ),
            padding=ft.Padding.symmetric(horizontal=10, vertical=8),
            bgcolor=COLORS["bg"],
            border_radius=SPACING["radius"],
        )

    def _format_size(self, value):
        try:
            size = int(value or 0)
        except (TypeError, ValueError):
            size = 0
        if size >= 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024 * 1024):.2f} GiB"
        if size >= 1024 * 1024:
            return f"{size / (1024 * 1024):.2f} MiB"
        if size >= 1024:
            return f"{size / 1024:.1f} KiB"
        return f"{size} B"

    def build(self) -> ft.Control:
        register_page_services(self.page, self.directory_picker)
        self._refresh_dirs()
        self._render_results()
        self._maybe_auto_scan()
        return ft.Container(
            content=ft.Column(
                [
                    ft.Text(
                        "Library",
                        size=TYPE["page_title"]["size"],
                        weight=ft.FontWeight.W_600,
                        color=COLORS["text_primary"],
                    ),
                    ft.Text(_WARNING, size=TYPE["caption"]["size"], color=COLORS["text_secondary"]),
                    card_panel(
                        "Monitored Directories",
                        [
                            ft.Row([self.add_button, self.scan_button], spacing=10),
                            ft.Container(
                                content=self.dir_list,
                                height=140,
                                padding=10,
                                bgcolor=COLORS["bg"],
                                border_radius=SPACING["radius"],
                            ),
                        ],
                    ),
                    card_panel(
                        "Search",
                        [
                            ft.Row([self.search_field, self.clear_search_button], spacing=10),
                        ],
                    ),
                    card_panel(
                        "Vaults",
                        [
                            ft.Container(
                                content=self.results_list,
                                height=440,
                                padding=10,
                                bgcolor=COLORS["bg"],
                                border_radius=SPACING["radius"],
                            ),
                        ],
                    ),
                ],
                spacing=18,
                scroll=ft.ScrollMode.AUTO,
                horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
            ),
            padding=24,
            expand=True,
        )
