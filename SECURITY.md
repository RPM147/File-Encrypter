# Security Model & Limitations

RPM Encrypter is a **local-only, single-user desktop tool**. It is not a service, has no server, and makes no network connections to perform encryption. This document describes the threat model it is designed for and, just as importantly, what it does **not** protect against. Read it before relying on the app for sensitive data.

## Threat model (what it is designed for)

RPM Encrypter protects the **confidentiality and integrity of files at rest** on a machine you control:

- **Confidentiality:** file contents, names, and the file manifest are sealed inside an AES-256-GCM-encrypted block; without the password they cannot be read.
- **Integrity / tamper-evidence:** AES-256-GCM is authenticated, so any modification of a vault is detected on decryption. The app fails rather than returning altered data.
- **Key derivation:** passwords are stretched with Argon2id, a memory-hard password hashing function, to make brute-forcing a stolen vault expensive.
- **Offline operation:** encryption and decryption happen entirely on your device.

It is intended for a single user protecting their own files against someone who later obtains the **vault files**: a lost laptop, a stolen drive, a shared computer, or a cloud-sync copy.

## What it does NOT protect against

### Secure wipe is best-effort, not guaranteed erasure

The "Secure Wipe" feature overwrites your original plaintext file after encryption, but overwriting does **not** guarantee the data is unrecoverable on modern storage:

- **SSDs / flash:** wear-leveling, TRIM, and over-provisioning mean the controller usually writes elsewhere, leaving the original cells intact. Extra passes do not help; the app's Health Check says so.
- **Filesystems:** journaling, copy-on-write filesystems such as APFS, Btrfs, and ReFS, plus filesystem snapshots, can keep old copies.
- **Elsewhere:** OS file caches, swap, hibernation files, thumbnails, temporary files, and backups may retain the data.

For reliable erasure, use **full-disk encryption from the start** or physically destroy the medium.

### Hidden vaults: plausible deniability is heuristic, not proof

A hidden vault lets one file carry a decoy payload, unlocked by the first password, and a hidden payload, unlocked by the second password. The format avoids obvious tells: a random "probe" hidden-salt is always present, and every password attempt performs the same work so normal and hidden vaults are timing-indistinguishable. Still:

- An adversary who can take **multiple snapshots** of the same vault over time may detect that its free-space region changes. That can be evidence a hidden vault exists and is in use.
- File size, timing, or your own workflow can raise suspicion.
- **No tool defends against coercion.** If someone can compel you to reveal passwords, deniability may not protect you. They may simply refuse to believe a denial.

Use hidden vaults as defense-in-depth, not as a guarantee.

### Memory zeroization: secrets may remain in RAM

Python cannot reliably erase secrets from memory. Passwords and derived keys live in immutable `str` and `bytes` objects that Python's garbage collector may copy, and they may be paged to swap or a hibernation file. The app does **not** wipe derived keys from RAM, and it could not do so reliably in pure Python.

Assume secrets can persist in RAM, swap, or hibernation storage until reboot. Use OS full-disk encryption and consider disabling swap or hibernation for high-sensitivity work.

### Lockout protects the app, not the file

After 5 wrong passwords the app enforces a 30-second lockout, but it is an **in-memory, per-session** limit. It resets when the app restarts and only guards the app's own decrypt and inspect flows.

Anyone with a copy of your `.vault` file can brute-force it **offline** with other tools, ignoring the lockout entirely. Your real protection against brute force is **Argon2id plus a strong password**. Choose a long, high-entropy passphrase.

### Other limitations

- **Lost credentials = lost data.** If you lose both your password and your recovery phrase, the data is unrecoverable by design.
- **Large-item plaintext is released before final verification.** For very large items the current format writes decrypted output to an app-owned temporary file before the authentication tag is checked ("release of unverified plaintext"). The output is app-owned, is not used until verification succeeds, and is securely wiped on failure. A future v4 chunked-AEAD format will verify each chunk before release.
- **Host trust.** RPM Encrypter cannot protect against a compromised operating system, malware, a keylogger, or a hardware implant on the machine where you type your password.

## Reporting a vulnerability

This is a personal/open-source project. If you find a security issue, please open an issue without including sensitive exploit details in public, or contact the maintainer.
