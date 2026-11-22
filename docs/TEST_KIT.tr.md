# Kombinasyonel Geçerli Özellik Test Kiti

> English: [TEST_KIT.md](TEST_KIT.md)

RPM Encrypter kombinasyonel test kiti, dört workspace paketindeki (`rpm-core`, `rpm-storage`, `rpm-cli`, `rpm-gui`) **tüm geçerli özellik kombinasyonlarını** sistematik biçimde doğrular. Kapsam gereği zorunlu kısıtlar ve negatif senaryolar (örneğin `--stealth` ile `--reed-solomon` birlikte seçimi veya dolgulu kasalarda `rekey`) bu kitin dışında bırakılmış olup mevcut güvenlik/dayanıklılık testlerinde test edilmeye devam eder.

## Test Paketleri ve Kombinasyon Kapsamı

### 1. Çekirdek Kripto ve Biçim Matrisi ([combinatorial_core_matrix.rs](../crates/rpm-core/tests/combinatorial_core_matrix.rs))
- **`core_vault_matrix_standard_24` / `core_vault_matrix_stealth_24` / `core_vault_matrix_reed_solomon_24` (toplam 72 yapılandırma):**
  Tam Kartezyen çarpım:
  - `EnvelopeMode`: `{Standard, Stealth, ReedSolomon}` (3)
  - `ContainerLayout`: `{Dolgusuz, Dolgulu (128 KiB), Gizli Kasa (160 KiB)}` (3)
  - `outer_compress`: `{false, true}` (2)
  - `outer_keyfile`: `{false, true}` (2)
  - `Hidden` için: `hidden_compress` (`{false, true}`) × `hidden_keyfile` (`{false, true}`) (4)
  - Her yapılandırmada 24 kelimelik BIP-39 kurtarma cümlesi gidiş-dönüşünü, başlık/boyut değişmezlerini, parolasız `check_integrity`, `inspect_header_seekable_with_kdf`, dış Parola / dış Kurtarma Anahtarı / Gizli Parola ile akış çözmeyi, `diff_metadata`, tüm `ReedSolomon` kasalarda `512` baytlık ardışık sektör bozulması + `repair_vault_stream` onarımını ve `Standard + Dolgusuz` kasalarda tüm geçerli `rekey_stream` anahtar/keyfile geçişlerini doğrular.
- **`core_chunk_size_and_payload_boundary_matrix` (75 koşu):**
  `3` zarf modu × `2` parça boyutu (`16 KiB`, `64 KiB`) × `2` sıkıştırma × `6` sınır uzunluk (`0`, `1`, `chunk-1`, `chunk`, `chunk+1`, `2*chunk+17`) ve tüm 3 modda `1 MiB + 13` varsayılan parça boyutu testi.
- **`core_argon2id_kdf_profile_matrix` (19 koşu):**
  `4` geçerli Argon2id profili (`16 MiB/1/1`, `16 MiB/2/4`, `32 MiB/2/2`, OWASP `64 MiB/3/4`) × `{Standard, Padded, Hidden, ReedSolomon}` ile ayrıca `{Unpadded, Padded, Hidden}` düzenlerinde gerçek üretim `STEALTH_KDF_PARAMS` (`64 MiB/3/4`) doğrulaması.
- **`core_diff_full_state_matrix`:**
  Eklenen, silinen, boyutu/zaman damgası/her ikisi değişen, değişmeyen, boş↔dolu, özdeş ve yönlü (`A→B` / `B→A`) karşılaştırma simetrisi.

### 2. Depolama İş Akışı Matrisi ([combinatorial_storage_matrix.rs](../crates/rpm-storage/tests/combinatorial_storage_matrix.rs))
- **`storage_vault_matrix_standard_24` / `storage_vault_matrix_stealth_24` / `storage_vault_matrix_reed_solomon_24` (toplam 72 yapılandırma):**
  Aynı 72'li matrisi Türkçe UTF-8 metin (`Iğdır-ölçü.txt`), PNG görseli, ikili dosya, `0 B` dosya, iç içe klasör ve boş klasör içeren gerçek dizinler üzerinde uçtan uca koşar; `.rpm_tmp_*` artığı olmadığını, uzantısız/farklı uzantılı Stealth dosyalarını, `512 B` hasarlı RS kasada şeffaf RAM önizleme (`extract_entry_to_memory_v5_with_stealth_kdf`), seçici çıkarma, tam çözme, kopyaya/yerinde `repair_vault_v5` ve `rekey_vault_v5` işlemlerini doğrular.
- **`storage_payload_edge_cases_and_stealth_self_exclusion_matrix`:**
  `3` mod × `2` sıkıştırma ile farklı klasörlerden aynı adlı dosya çakışmaları, Unicode/emoji adları, `0 B` dosya, boş klasör, `unique_path` ad çakışmaları, Stealth çıktısının kaynak klasör içine yazıldığında kendini dışlaması ve sembolik bağlantı atlama davranışı.
- **`storage_wipe_passes_and_output_modes_matrix` (60 koşu):**
  `wipe_passes ∈ 1..=5` × `3` mod × `{tek dosya, iç içe klasör}` × `{kaynak yanı, özel çıktı dizini}`.
- **`storage_config_launch_and_shell_integration_matrix`:**
  Geçici dizinde `AppConfig` kalıcılığı (`ThemeMode` × `AppLanguage` × ölçek × sıkıştırma × silme geçişi × Argon2id profilleri), tüm geçerli `parse_gui_launch_args` girişleri ve `MemoryRegistryBackend` üzerinden izole kur/durum/kaldır yaşam döngüsü (gerçek `%APPDATA%` veya Windows kayıt defterine dokunmaz).

### 3. Başsız CLI Matrisi ([combinatorial_cli_matrix.rs](../crates/rpm-cli/tests/combinatorial_cli_matrix.rs))
- **`cli_vault_matrix_standard_24` / `cli_vault_matrix_stealth_24` / `cli_vault_matrix_reed_solomon_24` (toplam 72 yapılandırma):**
  `rpm_cli::run_cli_args` ile `--recovery-out` ve stdout kurtarma cümlesi, `-o` ve kaynak yanı çıktı, `--progress {auto, always, never}`, `--wipe`, `.bin`/uzantısız Stealth yeniden adlandırma, `inspect --integrity-only` (`--json`/düz), RS `512 B` hasar onarımı (`repair -o` ve yerinde `repair`), `--password-stdin` ve `--recovery-stdin` ile `inspect` / `decrypt` / tekrarlanabilir `--only`, `diff` ve `rekey` geçişlerini çalıştırır.
- **`cli_batch_decrypt_diff_password_and_shell_status_matrix`:**
  Çoklu kasa toplu `decrypt`, tüm geçerli kimlik çiftleriyle `diff`, `--length {12,16,24,32,64}` × `{varsayılan, --no-symbols}` parola üretimi ve salt okunur `shell-integration status`.

### 4. Masaüstü GUI Durum, Çizim ve İşçi Matrisi ([combinatorial_gui_matrix.rs](../crates/rpm-gui/tests/combinatorial_gui_matrix.rs))
- **`gui_pwgen_full_150_cartesian_matrix` (150 yapılandırma):**
  Boş olmayan `15` karakter sınıfı alt kümesi × `exclude_ambiguous` × `length ∈ {12, 16, 24, 32, 64}` çarpımı, TR/EN `zxcvbn` puanlaması ve 30 sn pano zamanlayıcısı.
- **`gui_settings_theme_lang_scale_and_all_tabs_headless_render_matrix`:**
  İzole tema × dil × `7` ölçek × Argon2id/sıkıştırma/silme kaydı ve tüm 6 sekmenin (`Encrypt`, `Decrypt`, `Inspect`, `Rekey`, `Password`, `Settings`) TR/EN × Koyu/Açık altında başsız `egui::Context::run_ui` çizimi.
- **`gui_encrypt_container_presets_and_mode_matrix`:**
  Tüm `ContainerSizePreset` seçenekleri × `{Normal, Stealth, ReedSolomon}` × gizli/sıkıştırma/keyfile/çıktı seçenekleri.
- **`gui_preview_all_5_image_formats_multipage_utf8_and_lifecycle_matrix`:**
  Desteklenen `5` görsel biçimi (`PNG`, `JPEG`, `WebP`, `GIF`, `BMP`), kısa ve `>16 KiB` çok sayfalı UTF-8 metin, ikili dosya uyarısı ve `clear_preview` / `Esc` / sekme değişimi / `reset_manifest` temizlik doğrulamaları.
- **`gui_drag_drop_shortcuts_launch_and_manifest_filter_matrix`:**
  Tüm `6` aktif sekmede dosya/klasör/Stealth/kasa sürükle-bırak yönlendirmesi, `Ctrl+1..6` kısayolları, `Esc` modal kapatma ve manifest arama/seçme.
- **`gui_workers_all_10_operations_and_bilingual_reports_matrix`:**
  Tüm `10` arka plan işçisini (`spawn_encrypt`, `spawn_encrypt_hidden`, `spawn_integrity_check`, `spawn_repair`, `spawn_inspect`, `spawn_preview`, `spawn_selective_extract`, `spawn_decrypt`, `spawn_vault_diff`, `spawn_rekey`) Standart, Dolgulu, Gizli, hasarlı Reed-Solomon ve üretim-KDF Stealth kasalar üzerinde TR/EN rapor hizalama denetimiyle çalıştırır.

## Temel Sağlamlaştırma Kalkanları (`cargo test --workspace` içinde)

- **Dondurulmuş `v4.4.0` Altın Kasa Uyumluluğu ([golden_compatibility_tests.rs](../crates/rpm-core/tests/golden_compatibility_tests.rs), [golden_storage_compatibility_tests.rs](../crates/rpm-storage/tests/golden_storage_compatibility_tests.rs)):**
  [crates/rpm-core/tests/fixtures/v4_4_0/](../crates/rpm-core/tests/fixtures/v4_4_0/) altındaki 8 değiştirilmez `v4.4.0` müze kasasını (`golden.key` ve `fixtures_manifest.json` dahil toplam `304.231` bayt) okuyarak SHA-256 doğruluğunu, parola + 24 kelimelik kurtarma açılışını, gizli bölmeleri, RAM önizlemeyi, kasalar arası `diff` ve `512 B` RS onarımını doğrular.
- **Deterministik Bozuk Girdi Fuzzing ve Tar/Gzip Geri Alma ([fuzz_malformed_inputs.rs](../crates/rpm-core/tests/fuzz_malformed_inputs.rs), [fuzz_storage_inputs.rs](../crates/rpm-storage/tests/fuzz_storage_inputs.rs)):**
  `RPM_FUZZ_SEED` / `RPM_FUZZ_ITERS` ile tekrar üretilebilir `SplitMix64` mutasyon testleri çekirdek başlık/Stealth/RS/diff ve depolama açma/önizleme/onarım yollarını bombalar; ayrıca kötü niyetli arşivlerin (Tar-Slip `..`/`\`/sürücü önekleri, symlink/hardlink, bozuk gzip CRC32 sonluğu) temizce reddedildiğini doğrular.
- **Tepe RAM ve Tek-Geçiş I/O Regresyon Kilidi ([perf_and_memory_guard.rs](../crates/rpm-core/tests/perf_and_memory_guard.rs)):**
  `16 MiB` Standart, RS ve Stealth akışlarında sınırlı O(1) heap belleği ile `~1×` tek okuma geçişi I/O sınırını korur; ayrıca `.\scripts\run-benchmarks.ps1` üzerinden `--release` hız tablosunu üretir.

## Yerel Çalıştırma

```powershell
# Yalnızca dört kombinasyonel test paketini çalıştır (debug)
.\scripts\run-combinatorial-tests.ps1

# Dört kombinasyonel paketi eniyilenmiş --release modunda çalıştır
.\scripts\run-combinatorial-tests.ps1 -Release

# Kombinasyonel kit + rustfmt, Clippy (-D warnings) ve tüm workspace testlerini çalıştır
.\scripts\run-combinatorial-tests.ps1 -FullWorkspace

# 16 MiB --release aktarım hızı ve RAM benchmarkını çalıştır
.\scripts\run-benchmarks.ps1
```
