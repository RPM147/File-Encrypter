//! Self-contained, zero-JavaScript, offline printable HTML recovery sheet generator.
//!
//! Security properties:
//! - Validates the 24-word BIP-39 mnemonic before rendering (`rpm_core::mnemonic_to_entropy`).
//! - Escapes all interpolated dynamic text (`&`, `<`, `>`, `"`, `'`).
//! - Embeds a strict `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline';`
//!   meta header with zero scripts and zero external links/fonts/resources.
//! - Intentionally omits any hidden-compartment or container-padding metadata (`INV-06`).
//! - Holds rendered HTML in `Zeroizing<String>` and writes atomically (`0o600` on Unix).

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rpm_core::mnemonic_to_entropy;
use zeroize::Zeroizing;

use crate::atomic::atomic_write;
use crate::config::AppLanguage;
use crate::error::StorageError;
use crate::packager::format_unix_rfc3339;

/// Non-sensitive display metadata paired with a validated 24-word BIP-39 recovery phrase.
///
/// Deliberately contains no hidden-vault, decoy, or container-padding flags so printed sheets
/// can never disclose plausible-deniability structure (`INV-06`).
#[derive(Clone, Debug)]
pub struct RecoverySheetInfo<'a> {
    pub phrase: &'a str,
    pub vault_label: Option<&'a str>,
    pub created_at_utc: Option<&'a str>,
    pub has_keyfile: bool,
    pub language: AppLanguage,
}

fn escape_html(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn utc_now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_unix_rfc3339(secs)
}

/// Build a filesystem-safe default filename such as `Archive-recovery-sheet.html`.
pub fn suggested_recovery_sheet_filename(vault_label: Option<&str>) -> String {
    let raw_stem = vault_label
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            let stripped = s.strip_suffix(".001").unwrap_or(s);
            stripped
                .strip_suffix(".vault")
                .or_else(|| stripped.strip_suffix(".VAULT"))
                .unwrap_or(stripped)
        })
        .unwrap_or("vault");

    let mut clean = String::with_capacity(raw_stem.len().min(64));
    for ch in raw_stem.chars() {
        if clean.len() >= 64 {
            break;
        }
        if ch.is_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            clean.push(ch);
        } else {
            clean.push('_');
        }
    }
    let clean = clean.trim_matches(|c| c == '.' || c == '_');
    if clean.is_empty() {
        "vault-recovery-sheet.html".to_owned()
    } else {
        format!("{clean}-recovery-sheet.html")
    }
}

struct SheetLabels {
    html_lang: &'static str,
    title: &'static str,
    subtitle: &'static str,
    lbl_vault: &'static str,
    lbl_created: &'static str,
    lbl_format: &'static str,
    lbl_keyfile: &'static str,
    keyfile_yes: &'static str,
    keyfile_no: &'static str,
    grid_heading: &'static str,
    grid_hint: &'static str,
    warn_heading: &'static str,
    warn_bullets: [&'static str; 3],
    howto_heading: &'static str,
    howto_body: &'static str,
    notes_heading: &'static str,
    footer_print_tip: &'static str,
}

const TR_LABELS: SheetLabels = SheetLabels {
    html_lang: "tr",
    title: "Acil Durum Kurtarma Kartı",
    subtitle: "RPM Encrypter • Vault Format v5 (24 Kelimelik BIP-39 Kurtarma Anahtarı)",
    lbl_vault: "Kasa Adı",
    lbl_created: "Oluşturulma (UTC)",
    lbl_format: "Biçim",
    lbl_keyfile: "Anahtar Dosyası (Keyfile)",
    keyfile_yes: "Parolayla açılışta bağlı — 24 kelimelik kurtarma için gerekmez",
    keyfile_no: "Bağlı değil — 24 kelimelik kurtarma için gerekmez",
    grid_heading: "24 Kelimelik Kurtarma Cümlesi (Sırasıyla Giriniz)",
    grid_hint: "Büyük/küçük harf duyarsız, tek boşlukla ayrılmış 24 İngilizce BIP-39 kelimesi.",
    warn_heading: "KRİTİK GÜVENLİK UYARISI",
    warn_bullets: [
        "Bu kartı hemen çevrimdışı olarak yazdırın (Ctrl+P) ve yazdırdıktan sonra bu .html dosyasını diskten kalıcı olarak silin.",
        "Bu 24 kelimeye sahip herhangi biri, parola veya anahtar dosyası olmadan kasayı açabilir.",
        "Yazdırılan kâğıdı şifreli .vault yedeklerinizden fiziksel olarak ayrı ve güvenli bir yerde saklayın.",
    ],
    howto_heading: "Nasıl Kurtarılır?",
    howto_body: "RPM Encrypter uygulamasında Çöz (veya İncele) sekmesini açıp 'Parola yerine 24 kelimelik kurtarma cümlesi kullan' seçeneğini işaretleyin (CLI: rpm-encrypter-cli decrypt <kasa> --recovery) ve yukarıdaki 24 kelimeyi 01'den 24'e sırayla girin.",
    notes_heading: "Fiziksel Yedek / Konum Notları (Yazdırdıktan Sonra Elle Doldurun)",
    footer_print_tip: "Tamamen çevrimdışı belge — JavaScript ve harici ağ bağlantısı içermez. Yazdırmak için Ctrl+P / Cmd+P kullanın.",
};

const EN_LABELS: SheetLabels = SheetLabels {
    html_lang: "en",
    title: "Emergency Recovery Sheet",
    subtitle: "RPM Encrypter • Vault Format v5 (24-Word BIP-39 Recovery Key)",
    lbl_vault: "Vault Label",
    lbl_created: "Created (UTC)",
    lbl_format: "Format",
    lbl_keyfile: "Keyfile Binding",
    keyfile_yes: "Bound for password unlock — NOT required for 24-word recovery",
    keyfile_no: "None — NOT required for 24-word recovery",
    grid_heading: "24-Word Recovery Phrase (Enter in Exact Order)",
    grid_hint: "24 lowercase English BIP-39 words separated by single spaces.",
    warn_heading: "CRITICAL SECURITY WARNING",
    warn_bullets: [
        "Print this sheet offline immediately (Ctrl+P), then securely delete this .html file from disk.",
        "Anyone holding these 24 words can unlock the vault without the password or keyfile.",
        "Store the printed sheet physically separate from your encrypted .vault backups.",
    ],
    howto_heading: "How to Recover",
    howto_body: "Open the Decrypt (or Inspect) tab in RPM Encrypter, check 'Use 24-word recovery phrase instead of password' (CLI: rpm-encrypter-cli decrypt <vault> --recovery), and enter words 01 through 24 in order.",
    notes_heading: "Physical Backup / Storage Notes (Fill In by Hand After Printing)",
    footer_print_tip: "100% offline document — zero JavaScript and zero external network requests. Press Ctrl+P / Cmd+P to print.",
};

/// Validate the 24-word BIP-39 phrase and render a self-contained, offline printable HTML sheet.
pub fn render_recovery_sheet_html(
    info: &RecoverySheetInfo<'_>,
) -> Result<Zeroizing<String>, StorageError> {
    // Cryptographically validate the mnemonic (word list + checksum) before rendering.
    let _verified_entropy = mnemonic_to_entropy(info.phrase)?;
    let words: Vec<&str> = info.phrase.split_whitespace().collect();
    if words.len() != 24 {
        return Err(StorageError::InvalidPath(format!(
            "recovery phrase must contain exactly 24 words (got {})",
            words.len()
        )));
    }

    let lbl = match info.language {
        AppLanguage::Tr => &TR_LABELS,
        AppLanguage::En => &EN_LABELS,
    };

    let vault_label = info
        .vault_label
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(escape_html)
        .unwrap_or_else(|| "—".to_owned());
    let created_owned = info
        .created_at_utc
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(escape_html)
        .unwrap_or_else(|| escape_html(&utc_now_rfc3339()));
    let keyfile_text = if info.has_keyfile {
        lbl.keyfile_yes
    } else {
        lbl.keyfile_no
    };

    let mut html = Zeroizing::new(String::with_capacity(6144));
    let _ = write!(
        html,
        r#"<!DOCTYPE html>
<html lang="{html_lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<title>RPM Encrypter — {title}</title>
<style>
  @page {{ size: A4 portrait; margin: 14mm; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    padding: 24px;
    background: #f5f6f8;
    color: #111827;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    line-height: 1.45;
  }}
  .sheet {{
    max-width: 780px;
    margin: 0 auto;
    background: #ffffff;
    border: 1.5px solid #1f2937;
    border-radius: 8px;
    padding: 24px 28px;
  }}
  .header {{
    border-bottom: 2px solid #111827;
    padding-bottom: 12px;
    margin-bottom: 16px;
  }}
  .header h1 {{
    margin: 0 0 4px 0;
    font-size: 22px;
    letter-spacing: -0.01em;
  }}
  .subtitle {{
    margin: 0;
    font-size: 13px;
    color: #374151;
  }}
  .meta {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px 16px;
    margin-bottom: 18px;
    padding: 10px 12px;
    border: 1px solid #d1d5db;
    border-radius: 6px;
    background: #f9fafb;
    font-size: 12.5px;
  }}
  .meta-row {{
    display: flex;
    flex-direction: column;
  }}
  .meta-row.wide {{
    grid-column: 1 / -1;
  }}
  .meta-label {{
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: #4b5563;
    font-weight: 600;
  }}
  .meta-value {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 13px;
    word-break: break-all;
    color: #111827;
  }}
  .section-title {{
    margin: 0 0 4px 0;
    font-size: 14px;
    font-weight: 700;
  }}
  .section-hint {{
    margin: 0 0 10px 0;
    font-size: 12px;
    color: #4b5563;
  }}
  .word-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 8px;
    margin-bottom: 18px;
    page-break-inside: avoid;
  }}
  .word-cell {{
    border: 1px solid #374151;
    border-radius: 5px;
    padding: 7px 9px;
    display: flex;
    align-items: baseline;
    gap: 7px;
    background: #ffffff;
  }}
  .word-idx {{
    font-size: 11px;
    font-weight: 700;
    color: #4b5563;
    min-width: 20px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }}
  .word-text {{
    font-size: 14px;
    font-weight: 700;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    color: #000000;
    letter-spacing: 0.02em;
  }}
  .warning {{
    border: 1.5px solid #991b1b;
    background: #fef2f2;
    border-radius: 6px;
    padding: 10px 14px;
    margin-bottom: 16px;
    page-break-inside: avoid;
  }}
  .warning-title {{
    margin: 0 0 6px 0;
    font-size: 13px;
    font-weight: 800;
    color: #991b1b;
    letter-spacing: 0.03em;
  }}
  .warning ul {{
    margin: 0;
    padding-left: 18px;
    font-size: 12.5px;
    color: #1f2937;
  }}
  .warning li {{
    margin-bottom: 4px;
  }}
  .howto {{
    margin-bottom: 16px;
    font-size: 12.5px;
    color: #1f2937;
  }}
  .howto p {{
    margin: 4px 0 0 0;
  }}
  .notes {{
    margin-bottom: 14px;
    page-break-inside: avoid;
  }}
  .note-line {{
    border-bottom: 1px dashed #9ca3af;
    height: 24px;
  }}
  .footer {{
    border-top: 1px solid #d1d5db;
    padding-top: 8px;
    font-size: 11px;
    color: #4b5563;
    text-align: center;
  }}
  @media print {{
    body {{
      background: #ffffff;
      padding: 0;
    }}
    .sheet {{
      border: 1px solid #000000;
      border-radius: 0;
      max-width: none;
      padding: 16px 20px;
    }}
    .meta, .warning {{
      background: #ffffff;
    }}
    .warning {{
      border-color: #000000;
    }}
    .warning-title {{
      color: #000000;
    }}
  }}
</style>
</head>
<body>
<main class="sheet">
  <header class="header">
    <h1>{title}</h1>
    <p class="subtitle">{subtitle}</p>
  </header>

  <section class="meta">
    <div class="meta-row">
      <span class="meta-label">{lbl_vault}</span>
      <span class="meta-value">{vault_label}</span>
    </div>
    <div class="meta-row">
      <span class="meta-label">{lbl_created}</span>
      <span class="meta-value">{created_owned}</span>
    </div>
    <div class="meta-row">
      <span class="meta-label">{lbl_format}</span>
      <span class="meta-value">Vault Format v5 (AES-256-GCM + Argon2id)</span>
    </div>
    <div class="meta-row">
      <span class="meta-label">{lbl_keyfile}</span>
      <span class="meta-value">{keyfile_text}</span>
    </div>
  </section>

  <section>
    <h2 class="section-title">{grid_heading}</h2>
    <p class="section-hint">{grid_hint}</p>
    <div class="word-grid">
"#,
        html_lang = lbl.html_lang,
        title = escape_html(lbl.title),
        subtitle = escape_html(lbl.subtitle),
        lbl_vault = escape_html(lbl.lbl_vault),
        vault_label = vault_label,
        lbl_created = escape_html(lbl.lbl_created),
        created_owned = created_owned,
        lbl_format = escape_html(lbl.lbl_format),
        lbl_keyfile = escape_html(lbl.lbl_keyfile),
        keyfile_text = escape_html(keyfile_text),
        grid_heading = escape_html(lbl.grid_heading),
        grid_hint = escape_html(lbl.grid_hint),
    );

    for (idx, word) in words.iter().enumerate() {
        let _ = writeln!(
            html,
            r#"      <div class="word-cell"><span class="word-idx">{:02}.</span><span class="word-text">{}</span></div>"#,
            idx + 1,
            escape_html(word)
        );
    }

    let _ = write!(
        html,
        r#"    </div>
  </section>

  <section class="warning">
    <p class="warning-title">{warn_heading}</p>
    <ul>
      <li>{w0}</li>
      <li>{w1}</li>
      <li>{w2}</li>
    </ul>
  </section>

  <section class="howto">
    <h2 class="section-title">{howto_heading}</h2>
    <p>{howto_body}</p>
  </section>

  <section class="notes">
    <h2 class="section-title">{notes_heading}</h2>
    <div class="note-line"></div>
    <div class="note-line"></div>
    <div class="note-line"></div>
  </section>

  <footer class="footer">{footer_print_tip}</footer>
</main>
</body>
</html>
"#,
        warn_heading = escape_html(lbl.warn_heading),
        w0 = escape_html(lbl.warn_bullets[0]),
        w1 = escape_html(lbl.warn_bullets[1]),
        w2 = escape_html(lbl.warn_bullets[2]),
        howto_heading = escape_html(lbl.howto_heading),
        howto_body = escape_html(lbl.howto_body),
        notes_heading = escape_html(lbl.notes_heading),
        footer_print_tip = escape_html(lbl.footer_print_tip),
    );

    Ok(html)
}

/// Atomically write the validated printable HTML recovery sheet to `path`.
/// On Unix, restricts file mode to `0o600` (owner read/write only).
pub fn write_recovery_sheet_html(
    path: &Path,
    info: &RecoverySheetInfo<'_>,
) -> Result<(), StorageError> {
    if path.is_dir() {
        return Err(StorageError::InvalidPath(format!(
            "recovery sheet output path is a directory: {}",
            path.display()
        )));
    }
    let html = render_recovery_sheet_html(info)?;
    atomic_write(path, |writer| {
        writer.write_all(html.as_bytes())?;
        Ok(())
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rpm_core::{entropy_to_mnemonic, generate_recovery_entropy};

    #[test]
    fn renders_offline_csp_locked_html_in_tr_and_en_without_hidden_leakage() {
        let entropy = generate_recovery_entropy();
        let phrase = entropy_to_mnemonic(&entropy).unwrap();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24);

        for lang in [AppLanguage::Tr, AppLanguage::En] {
            let html = render_recovery_sheet_html(&RecoverySheetInfo {
                phrase: phrase.as_str(),
                vault_label: Some("Archive.vault"),
                created_at_utc: Some("2026-11-26T15:00:00Z"),
                has_keyfile: true,
                language: lang,
            })
            .unwrap();

            assert!(html.contains("default-src 'none'; style-src 'unsafe-inline';"));
            assert!(html.contains("@media print"));
            assert!(!html.to_ascii_lowercase().contains("<script"));
            assert!(!html.contains("http://") && !html.contains("https://"));
            assert!(html.contains("Archive.vault"));
            assert!(html.contains("2026-11-26T15:00:00Z"));
            for (idx, word) in words.iter().enumerate() {
                assert!(
                    html.contains(&format!(
                        ">{:02}.</span><span class=\"word-text\">{word}<",
                        idx + 1
                    )),
                    "missing numbered word {:02} ({word})",
                    idx + 1
                );
            }
            // INV-06: Printable recovery sheets must never disclose hidden/decoy existence.
            let lower = html.to_lowercase();
            for forbidden in ["hidden", "decoy", "gizli", "sahte", "deniability", "inkâr"] {
                assert!(
                    !lower.contains(forbidden),
                    "recovery sheet leaked forbidden term '{forbidden}'"
                );
            }
        }
    }

    #[test]
    fn escapes_html_special_chars_and_rejects_invalid_mnemonic() {
        let entropy = generate_recovery_entropy();
        let phrase = entropy_to_mnemonic(&entropy).unwrap();

        let html = render_recovery_sheet_html(&RecoverySheetInfo {
            phrase: phrase.as_str(),
            vault_label: Some("<script>alert(\"x\")&'test'</script>.vault"),
            created_at_utc: Some("2026<tag>"),
            has_keyfile: false,
            language: AppLanguage::En,
        })
        .unwrap();
        assert!(!html.contains("<script>"));
        assert!(html.contains(
            "&lt;script&gt;alert(&quot;x&quot;)&amp;&#39;test&#39;&lt;/script&gt;.vault"
        ));
        assert!(html.contains("2026&lt;tag&gt;"));

        assert!(render_recovery_sheet_html(&RecoverySheetInfo {
            phrase: "not a valid bip39 phrase at all",
            vault_label: None,
            created_at_utc: None,
            has_keyfile: false,
            language: AppLanguage::En,
        })
        .is_err());
    }

    #[test]
    fn atomic_write_creates_parent_rejects_dir_and_suggests_safe_filename() {
        let dir = tempfile::tempdir().unwrap();
        let entropy = generate_recovery_entropy();
        let phrase = entropy_to_mnemonic(&entropy).unwrap();
        let info = RecoverySheetInfo {
            phrase: phrase.as_str(),
            vault_label: Some("My Backup.vault.001"),
            created_at_utc: None,
            has_keyfile: false,
            language: AppLanguage::Tr,
        };

        assert!(write_recovery_sheet_html(dir.path(), &info).is_err());

        let nested = dir.path().join("sheets").join("card.html");
        write_recovery_sheet_html(&nested, &info).unwrap();
        let content = std::fs::read_to_string(&nested).unwrap();
        assert!(content.contains("Acil Durum Kurtarma Kartı"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&nested).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        assert_eq!(
            suggested_recovery_sheet_filename(Some("Archive.vault")),
            "Archive-recovery-sheet.html"
        );
        assert_eq!(
            suggested_recovery_sheet_filename(Some("Archive.vault.001")),
            "Archive-recovery-sheet.html"
        );
        assert_eq!(
            suggested_recovery_sheet_filename(Some("Iğdır/a:b*c.vault")),
            "Iğdır_a_b_c-recovery-sheet.html"
        );
        assert_eq!(
            suggested_recovery_sheet_filename(Some("...")),
            "vault-recovery-sheet.html"
        );
        assert_eq!(
            suggested_recovery_sheet_filename(None),
            "vault-recovery-sheet.html"
        );
    }
}
