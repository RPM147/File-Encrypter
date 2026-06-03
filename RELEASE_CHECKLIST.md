# RPM Encrypter — Release Smoke-Test Checklist

Run this entire checklist before tagging/publishing any release. RPM Encrypter is a
**local-only desktop app** — every step is performed on your own machine; no server
or network is involved (except the optional, off-by-default update check in the legacy
interface). All steps are **manual** unless marked *(automated)*.

The shipped UI is the modern **Flet** app (`app_flet.py`); the legacy **CustomTkinter**
app (`gui_app.py`) is kept as a fallback. Run the GUI smoke tests below against the Flet
app. If you also ship the legacy app, repeat at least sections 3–7 against it.

Local state files this app may create in your home directory (referenced throughout):

| Path | Purpose |
|------|---------|
| `~/.rpm_encrypter.json` | settings, recent-file lists, saved fingerprints, profiles |
| `~/.rpm_encrypter_activity.db` | activity log (only if you enable logging) |
| `~/.rpm_encrypter_library.json` | library/monitored-directory scan cache |
| `~/.rpm_encrypter/versions/` | saved vault versions (only if versioning is on) |
| system temp dir | transient config writes and operation temp zips/dirs |

## 0. Pre-flight (automated gates)
- [ ] *(automated)* `python -m pytest -q` → **all green** (symlink tests skip on Windows without Developer Mode)
- [ ] *(automated)* `python crypto_core.py` → all core self-tests pass
- [ ] App version bumped where applicable: `APP_VERSION` (About panel) and `[project].version` in `pyproject.toml` (the Flet build artifact version)
- [ ] `requirements.txt` installs cleanly in a fresh virtual environment (includes `flet==0.85.2`)
- [ ] *(Flet build only)* Windows **Developer Mode** is ON (`start ms-settings:developers`) — Flutter plugin builds need symlink support
- [ ] *(Flet build only)* `flutter doctor` shows Visual Studio with the **"Desktop development with C++"** workload **and the Windows 10/11 SDK** component (the SDK is installed separately from the compiler)

## 1. Build the release artifact(s)
- [ ] **Primary (Flet):** `.\build.ps1` → produces `build\windows\` ; the app launches from there
- [ ] Confirm the Flet build is **fully offline** — first launch makes **no** download of a Flet client from GitHub (the Flutter client is compiled into the build)
- [ ] *(optional, if shipping the fallback)* **Legacy (CustomTkinter):** `.\build.ps1 -Legacy` → produces `dist\RPM Encrypter.exe` ; it launches
- [ ] *(optional)* Custom Windows icon is present (`assets\icon.png` for the Flet build / `icon.ico` for the legacy build)

## 2. Clean install
- [ ] Use a fresh user profile / VM with **no** prior `~/.rpm_encrypter*` files or `~/.rpm_encrypter/` folder
- [ ] Install one of: the packaged Flet build (`build\windows\`), the packaged legacy build (`dist\`), or `pip install -r requirements.txt`
- [ ] Confirm none of the local-state files in the table above exist yet

## 3. Launch + first-run privacy
- [ ] Launch the Flet app (`python app_flet.py`, or the packaged executable) → main window opens, no crash
- [ ] First-run privacy notice is shown and states that update checks & activity logging are **OFF**
- [ ] Verify defaults are opt-in: update checks **OFF** and activity logging **OFF** by default

## 4. Encrypt / Decrypt — single file
- [ ] Encrypt a file with a strong password → a `.vault` is produced
- [ ] Decrypt it back → output is byte-identical to the original and the original filename is restored
- [ ] Decrypt with a wrong password → rejected with a clear error and no partial/garbage output

## 5. Encrypt / Decrypt — folder
- [ ] Encrypt a folder (multiple files + nested subfolders) → a single `.vault`
- [ ] Decrypt → full directory structure and file contents restored intact

## 6. Hidden vault (plausible deniability)
- [ ] Create a vault using BOTH a decoy password and a hidden password
- [ ] Decoy password opens the **decoy** data only
- [ ] Hidden password opens the **hidden** data
- [ ] The vault file size/header does not reveal that a hidden vault exists
- [ ] Decoy vs hidden vs wrong password are timing-indistinguishable (no obvious delay difference)

## 7. Recovery phrase
- [ ] During encryption, record the 24-word BIP-39 recovery phrase
- [ ] Confirm the dialog states the phrase recovers the **decoy/standard** content only (hidden payload is intentionally not recoverable by phrase)
- [ ] Confirm the mandatory "I have saved this phrase" acknowledgement is required before continuing
- [ ] Decrypt the vault using the recovery phrase (no password) → succeeds
- [ ] An edited/invalid phrase (bad word or checksum) is rejected

## 8. Re-key (password change)
- [ ] Re-key a vault from the old password to a new password → completes
- [ ] New password decrypts the vault; old password is rejected; payload is unchanged

## 9. Versioning (opt-in)
- [ ] Enable versioning in Settings (set max-per-vault, max-total-MB, and versions directory)
- [ ] Trigger a version save (re-encrypt/replace a vault) → a version appears under `~/.rpm_encrypter/versions/` (or the chosen directory)
- [ ] Restore a version (as a copy and via replace); confirm pruning honors the count and total-size limits

## 10. Inspect / integrity / fingerprints
- [ ] Inspect a vault → metadata is shown without fully decrypting the payload
- [ ] Compute the integrity SHA-256 and save a fingerprint
- [ ] Verify-vs-saved correctly reports "unchanged" for an untouched file and "mismatch" for a modified one
- [ ] *(if used)* Vault-diff compares two vaults by header only (no payload decryption)

## 11. Notes & password generator
- [ ] Encrypt a text note, then decrypt it → identical text
- [ ] Generate a password and copy it → the clipboard auto-clears (≈30s); a stale timer never clears a newer value

## 12. Update check (off by default)
- [ ] Fresh launch with default settings makes **no** network call of any kind
- [ ] In Settings, the "Check for updates on startup" toggle is **OFF** by default
- [ ] Toggle it ON → the `check_updates` setting persists across a restart
- [ ] Note: the Flet app persists this preference but performs **no** update network call (the actual background update check is wired only in the legacy CustomTkinter app). *(If shipping the legacy app: with the toggle ON and offline, the check fails silently/gracefully.)*

## 13. Activity logging toggle
- [ ] Enable activity logging → events are recorded to `~/.rpm_encrypter_activity.db`
- [ ] The settings label makes clear that logging stores filenames locally
- [ ] Disable logging → no new events are recorded

## 14. Local-trace cleanup
- [ ] Use **Clear All Local Traces** → it clears the activity log, the library cache (`~/.rpm_encrypter_library.json`), and the recent-file lists + saved fingerprints inside `~/.rpm_encrypter.json`
- [ ] Confirm console logs print **basenames only** (e.g. `secret.txt`), never full home-directory paths (Phase 29 hygiene)

## 15. Uninstall / residual files
- [ ] Close the app, then remove these for a fully clean uninstall (delete only those that exist):
  - [ ] `~/.rpm_encrypter.json`
  - [ ] `~/.rpm_encrypter_activity.db`
  - [ ] `~/.rpm_encrypter_library.json`
  - [ ] `~/.rpm_encrypter/versions/` (and the `~/.rpm_encrypter/` folder if empty)
  - [ ] any leftover operation temp files or temp zips in the system temp directory
- [ ] After removing the above plus the application files, no RPM Encrypter data remains on disk

## 16. Non-negotiable regression gate (from FIX.md)
These are covered by `pytest` + `python crypto_core.py`; confirm green before shipping:
- [ ] Normal encrypt/decrypt round-trip
- [ ] Wrong-password rejection
- [ ] Tampered header / encrypted metadata / payload / tag rejection
- [ ] Recovery-phrase checksum and decrypt
- [ ] Hidden vault: decoy password opens decoy data; hidden password opens hidden data
- [ ] Hidden vault header does not reveal existence (post format fix)
- [ ] M2 invariant: a password unlock performs exactly 2 Argon2 derivations (normal/hidden/wrong are timing-indistinguishable)
- [ ] Re-key preserves decryptability
- [ ] KDF bounds reject hostile values
- [ ] Zip-slip, symlink, and zip-bomb defenses
- [ ] Duplicate-basename archive restore
- [ ] Crash-safe temp cleanup simulation
- [ ] Atomic output failure simulation
