# Tasarım Değişmezleri ve Mühendislik Kuralları

> [English](DESIGN_INVARIANTS.md) (varsayılan) · **Türkçe** · Format Yapısı: [ARCHITECTURE.tr.md](../ARCHITECTURE.tr.md) · Tehdit Modeli: [SECURITY.tr.md](../SECURITY.tr.md)

Bu belge, RPM Encrypter (`v4.4.0+`) için **taviz verilemez mimari, kriptografik ve yönetim değişmezlerini** kayıt altına alır. Yeni özellikler, refaktörler veya otomatik ajan değişiklikleri; bilinçli ve onaylı bir ana biçim sürüm artışı (`VAULT_VERSION > 5`) yapılmadığı sürece aşağıdaki tüm kuralları korumak zorundadır.

---

## Kriptografik ve Biçim Değişmezleri

### `INV-01` — Vault Format v5 (`v4.4.0+`) Geriye Dönük Uyumluluk
- Yayımlanmış `v4.4.0+` sürümleriyle oluşturulmuş tüm kasalar (Standart, Sıkıştırılmış, Keyfile, Dolgulu, Gizli `RPMH`, Stealth ve Reed-Solomon `RPMR`) gelecekteki sürümlerde **birebir aynı biçimde doğrulanabilmeli, incelenebilmeli, onarılabilmeli ve çözülebilmelidir**.
- `v5` içindeki gelecek eklemeler kesinlikle geriye dönük eklemeli olmalı (veya yeni açık alan/imza sürümlerine bağlanmalı) ve birleştirmeden önce dondurulmuş altın kasa örnekleriyle test edilmelidir.

### `INV-02` — Doğrulanmamış Düz Metin Çıkışına Sıfır İzin
- Diske çözme işlemleri **yalnızca** kardeş gizli geçici klasöre (`.rpm_unpack_*.part`) açmalı ve son AEAD parçası (`final_flag == 1`) doğrulandıktan sonra atomik olarak hedefe taşımalıdır. Hata veya iptalde hedefte düz metin bırakılmadan geçici alan temizlenir.
- RAM-içi önizleme (`İncele -> Önizle`, varsayılan sınır `16 MiB`), bölmenin **tüm akışı** son AEAD parçasını doğrulayana kadar çözülmüş içeriği göstermemelidir.
- **CLI'da `--password` bayrağı yoktur** ve güvenilmeyen başlıklardan sınırsız bellek/KDF ayırması yapılamaz (JSON başlığı `MAX_HEADER_SIZE = 1 MiB` ile sınırlıdır, KDF parametreleri doğrulanır).

### `INV-03` — Tek-Geçiş Akış ve Sınırlı O(1) Bellek
- Şifreleme, çözme, inceleme, doğrulama ve Reed-Solomon onarımı parça parça / blok blok akışla (`O(chunk_size)` veya `O(RS_BLOCK_WIRE_SIZE)` bellek) çalışmalı; çok gigabaytlı kasalar asla bütün hâlinde RAM'e alınmamalıdır.
- Çözme, RS onarımı ve Stealth doğrulaması **tek okuma geçişinde (~`1×` I/O)** tamamlanmalı; akış çözmeden önce tüm dosyayı baştan sona okuyan ikinci bir ön-tarama geçidi eklenmemelidir.

### `INV-04` — Stealth Modu ile Reed-Solomon Kesin Karşılıklı Dışlaması
- `--stealth` ve `--reed-solomon` seçenekleri çekirdek, depolama, CLI ve GUI katmanlarında **her zaman birbirini dışlamalı** ve anında hata vermelidir.
- **Neden:** RS parite blokları sıfır-sendromlu matematiksel yapı ve `RPMR` başlığı üretir; bu da Stealth Modunun tekdüze rastgele baytlardan ayırt edilememe (1. katman inkar edilebilirlik) özelliğini bozar.

### `INV-05` — Stealth Sabit Güvenlik Profili ve Sıfır Geçici Dosya İzi
- Üretimde tüm Stealth kasaları (dolgusuz, dolgulu, gizli), kullanıcı KDF ayarlarından bağımsız olarak sabit `STEALTH_KDF_PARAMS` (`Argon2id 64 MiB / 3 yineleme / 4 paralellik`) kullanmalıdır (çünkü başlıkta KDF bilgisi taşınmaz).
- Yanlış parola, yanlış/eksik keyfile, bozuk veri veya kısa dosya hataları tekdüze biçimde `AuthenticationFailed` döndürerek keyfile ya da gizli bölme varlığını sızdırmamalıdır.
- Parolasız bütünlük kontrolü (`inspect --integrity-only` / GUI), `RPMV`/`RPMR` imzası taşımayan dosyalarda yalnızca dosya boyutu ve `SHA-256` hesaplamalıdır.
- Stealth oluşturma doğrudan özel yeni hedefe (`create_new`) yazarak `.rpm_tmp_*` geçici dosya izini önler; hata durumunda kısmi çıktıyı siler.

### `INV-06` — Makul İnkar Edilebilirlik Eşitliği ve `rekey` Kısıtı
- Standart dolgulu kasalar ile içinde gizli bölme (`RPMH`) bulunan kasalar bit düzeyinde birebir aynı açık `VaultHeader` düzenini (sıfır gizli bölme bayrağı), aynı hata davranışını ve `OsRng` dolgu dağılımını paylaşmalıdır.
- Dolgulu, Gizli, Stealth ve Reed-Solomon kasaları `rekey` işlemini `UnsupportedOperation` ile reddetmelidir (hem inkar edilebilirliği hem de RS parite bütünlüğünü korumak için).

---

## Uygulama, Güvenlik ve Yönetim Değişmezleri

### `INV-07` — Saf-Rust Güvenliği, Bellek Sıfırlama, Çevrimsiz Mimari ve Sıfır Telemetri
- Paket bağımlılığı kesin çevrimsizdir: `rpm-core` -> `rpm-storage` -> {`rpm-cli`, `rpm-gui`}.
- Saf-Rust protokol/hata düzeltme modülleri (`crates/rpm-core/src/rs.rs`) `#![forbid(unsafe_code)]` uygular. `unsafe` FFI yalnızca `zeroize` / `Zeroizing` korumalı `SecretKey` içindeki bellek kilitlemeyle (`VirtualLock`/`mlock`) sınırlıdır.
- Tüm bağımlılıklar `cargo-deny` (`deny.toml`) lisans/güvenlik açık/crates.io kurallarından geçmeli ve `Cargo.lock` `--locked` ile kilitli kalmalıdır.
- Sıfır telemetri, sıfır analiz ve sıfır ağ bağlantısı.

### `INV-08` — Kötü Niyetli Arşiv Çıkarma Sınırları
- Hem diske çıkarma hem RAM-içi önizleme her tar girdisini yol atlamasına (`..`, kök yol, Windows sürücü harfi, NUL baytı) karşı temizlemeli, sembolik/sabit bağlantıları atlamalı/reddetmeli, hedef kasa dosyasının kendi içine paketlenmesini engellemeli ve `UnpackLimits` sınırlarını (`max_path_depth = 128`, `max_file_count = 500_000`, `max_total_bytes = 64 GiB`) zorunlu kılmalıdır.

### `INV-09` — CI Kapıları, Bağımlılık Denetimi ve Tek Geliştirici `main` Güvenli Modu
- CI; `cargo fmt --all -- --check`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, `cargo test --locked --workspace --lib`, `cargo test --locked --workspace` (Windows + Linux) ve `cargo-deny` denetimlerini koşar.
- Bağımlılık güncellemeleri otomatik Dependabot PR dalları açılmadan doğrudan `main` üzerinde `cargo update` ile yapılır; her gönderimde `cargo-deny` güvenlik açığı, lisans ve kaynak denetimini zorunlu kılar.
- **GitHub `main` Dal Koruması (Tek Geliştirici Güvenli Mod):** **Repository Settings -> Rules -> Rulesets** altında **Default branch (`main`)** için **Restrict deletions** ve **Block force pushes** kuralları **Active** tutulur; böylece normal push akışı yavaşlamadan geçmiş silme/ezme kazaları önlenir.
