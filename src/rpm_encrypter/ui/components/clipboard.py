"""Token-guarded auto-clearing clipboard helper for Flet screens."""

import asyncio


class AutoClearClipboard:
    """Copies text to a Flet Clipboard service and clears it after a delay if unchanged."""

    def __init__(self, page, shell, services, clipboard_or_getter, clear_seconds: float = 30.0):
        self.page = page
        self.shell = shell
        self.services = services
        self._clipboard_ref = clipboard_or_getter
        self.clear_seconds = clear_seconds
        self.token = 0

    def _get_clipboard(self):
        if callable(self._clipboard_ref):
            return self._clipboard_ref()
        return self._clipboard_ref

    async def copy(
        self,
        text: str,
        *,
        copied_status: str = "Copied!",
        on_error=None,
    ) -> bool:
        try:
            await self._get_clipboard().set(text)
        except Exception as exc:
            if on_error is not None:
                on_error(exc)
            return False
        self.token += 1
        token = self.token
        self.shell.status_text.value = copied_status
        self.shell.safe_update()
        self.page.run_task(self.clear_after_delay, token)
        return True

    async def clear_after_delay(self, token: int) -> None:
        await asyncio.sleep(self.clear_seconds)
        await self.clear_if_current(token)

    async def clear_if_current(self, token: int) -> None:
        if token != self.token:
            return
        if getattr(self.services, "shutdown_requested", False):
            return
        try:
            await self._get_clipboard().set("")
        except Exception:
            return
        self.shell.status_text.value = "Clipboard cleared"
        self.shell.safe_update()
