# RPM Encrypter — Architecture & Compatibility Policy

## Package Layout

```text
src/
  main.py                       # Unified entry point (GUI + headless CLI routing)
  assets/icon.png               # Desktop bundle icon
  rpm_encrypter/
    cli.py                      # Flet-free CLI (encrypt, decrypt, inspect, rekey, shell-integration)
    core/                       # Cryptographic primitives, vault format v4, BIP-39 recovery
    storage/                    # Atomic I/O, wiping, zip packaging, inspection, scanner, versioning, config, SQLite log
    services/                   # Flet-free wiring, state, launch routing, Windows HKCU shell integration, events, controllers
    ui/                         # Flet shell, events, tokens, theme, reusable components/, dialogs/, screens/
launcher/                       # Windows Unicode-path C wrapper and .rc/.ico
tests/                          # Layered test suite (core, storage, services, ui, packaging/docs)
```

## Dependency Rules (Acyclic)

1. **`core`** depends only on the Python stdlib, `cryptography`, and `argon2-cffi`. It never imports `storage`, `services`, or `ui`.
2. **`storage`** may import `core`, never `services` or `ui`.
3. **`services`** (including `events.py`, `launch.py`, `shell_integration.py`, `BaseController`, and all `controllers/*`) may import `core` and `storage`. Typed `AppEvent` dataclasses in `services/events.py` define the worker-to-UI queue contract. It must remain **100% Flet-free** so business workflows are testable headlessly.
4. **`ui`** (including `components/*`, `dialogs/*`, and `screens/*`) wires Flet controls to `services`, `storage`, and `core`. Only `ui/events.py` stays Flet-free to simplify queue-dispatch testing.
5. **`cli.py`** and top-level **`main.py`** remain **100% Flet-free** at import time so headless commands (`encrypt`, `decrypt`, `inspect`, `rekey`, `shell-integration`) execute without loading Flet.

## Clean-Slate / No Backward Compatibility Policy

RPM Encrypter is being rebuilt cleanly from the ground up. **Backward compatibility with legacy code, legacy UI/config layouts, deprecated module paths, or compatibility shims is intentionally NOT maintained:**

- Old modules, symbols, and entry points are removed or renamed directly rather than bridged with re-export shims.
- Legacy CustomTkinter code (`gui_app.py`, `views/`, `widgets.py`, PyInstaller specs) and flat root-level Python modules have been retired permanently.
- Internal APIs (`storage`, `services`, `ui`) may be refactored freely to keep the codebase clean and cohesive.
- **Vault Format Policy:** Routine architectural and UI refactorings keep the active **Vault Format v4** untouched (`VAULT_VERSION = 4`). However, when an intentional breaking format revision (such as a future Chunked-AEAD v5 format) is introduced in a major release, backward compatibility with earlier vault formats is **not** guaranteed.
