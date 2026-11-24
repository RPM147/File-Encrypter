# RPM Encrypter

[![CI](https://github.com/RPM147/File-Encrypter/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/RPM147/File-Encrypter/actions/workflows/ci.yml)

**Dil / Language:** [English](README.md) (varsayılan) · **Türkçe**

RPM Encrypter; **Parçalı AES-256-GCM** (`Vault Format v5`), **Argon2id** anahtar türetme, isteğe bağlı **anahtar dosyası (keyfile) iki faktörlü bağlama** ve bellekte kesin sıfırlama (`zeroize` + `VirtualLock`/`mlock`) kullanan **Saf-Rust, yalnızca yerel** bir dosya şifreleme aracıdır.

Her şey tamamen yerel çalışır; sıfır telemetri, bulut hesabı veya ağ bağlantısı içermez. Emekliye ayrılmış Python + Flet (`Vault Format v4`) kod tabanı önceki Git geçmişinde korunmaktadır.

[Kullanım Kılavuzu (Türkçe)](docs/USER_GUIDE.tr.md) · [User Guide (English)](docs/USER_GUIDE.md) · [Değişiklik Günlüğü (Türkçe)](CHANGELOG.tr.md) · [Changelog (English)](CHANGELOG.md)

## Temel Özellikler

- **Parçalı Kimlik Doğrulamalı Şifreleme (Vault Format v5):** Düz metin akışları kasa bağlamına, parça dizinine, son parça bayrağına ve düz metin uzunluğuna bağlı bağımsız `1 MiB` AEAD parçaları hâlinde şifrelenip doğrulanır. Bozuk, sırası değiştirilmiş, kırpılmış veya sonradan eklenmiş veriler **diske tek bayt yazılmadan RAM’de reddedilir**.
- **Sıfır Geçici Düz Metin Dosyası:** Paketleme ve açma işlemleri diske ara `.zip`/`.tar` dosyası yazmadan bellekteki sınırlı boru (pipe) üzerinden doğrudan Parçalı AEAD akışına bağlanır.
- **Kesin Bellek Sıfırlama:** Parolalar, keyfile özetleri, DEK’ler ve parça tamponları bellekten düşerken sıfırlanır (`zeroize`) ve mümkün olan en iyi çabayla takas dosyasına karşı kilitlenir (Windows’ta `VirtualLock`, Unix’te `mlock`).
- **İsteğe Bağlı Anahtar Dosyası (Keyfile) İki Faktörlü Açılış:** Kasanızı boş olmayan herhangi bir anahtar dosyasına (SHA-256 özeti alınıp Argon2id anahtarıyla HKDF üzerinden karıştırılarak) bağlayın.
- **24 Kelimelik BIP-39 Kurtarma Cümleleri:** Parola slotundan ayrı saklanan acil durum kurtarma anahtarı slotu.
- **O(1) Anahtar Değiştirme (Re-Key):** Gigabaytlarca veri parçasını yeniden şifrelemek yerine yalnızca 32 baytlık DEK zarfını yeniden sararak parolaları ve/veya keyfile bağını güncelleyin.
- **Yerel Masaüstü Arayüzü + Sürükle-Bırak (`rpm-encrypter`):** `eframe`/`egui` ve `rfd` ile geliştirilmiştir; Türkçe/İngilizce arayüz (`TR`/`EN`), harici dosya/klasör sürükle-bırak desteği ve kopyalanan sırlar için isteğe bağlı 30 saniyelik otomatik pano temizleme zamanlayıcısı sunar.
- **Operasyonel Güvenlik, Profiller ve Toplu Kuyruk (GUI):** Sistem panosuna dokunmayan hareketsizlikte otomatik kilit ve manuel oturum temizleme (`Ctrl+L`), hazır ve özel şifresiz **Şifreleme Profilleri**, ön kontrolde kaynak boyutu / RS parite / konteyner sığma tahmincisi, işlem sonrası **Klasörde Göster** / **Şimdi Doğrula** hızlı aksiyonları ve sıfırlamalı sıralı **Toplu İş Kuyruğu** içerir.
- **Kasa Gezgini, Seçici Çıkarma ve Gelişmiş RAM-İçi Önizleme:** GUI **İncele** sekmesinde **Klasör Ağacı / Düz Liste** görünümüyle üç durumlu klasör seçimi, tür/boyut filtreleri ve seçici çıkarma yapın (veya CLI’da stage-and-swap korumalı tekrarlanabilir `decrypt --only <YOL>` bayrağını kullanın). `16 MiB`’a kadar dosyaları diske dokunmadan tamamen RAM’de önizleyin — satır numaralı ve `Ctrl+F` aramalı UTF-8 metinler, yakınlaştırma ve kayıpsız `90°` döndürmeli görseller, ikili dosyalar için ise salt okunur Hex + ASCII görünümü desteklenir.
- **Parçalı Kasa Bölme / Birleştirme (Sanal `Read + Seek`):** Büyük kasaları FAT32 (`4000 MiB`) veya yükleme sınırları için CLI (`--split-mb` / `split` / `join`) ya da GUI **Şifrele** ve **İncele** araçlarıyla numaralı parçalara (`.vault.001`, `.vault.002`, ...) bölün. `decrypt`, seçici çıkarma, RAM önizleme, `inspect`, `diff`, `rekey` ve Reed-Solomon `repair`; en fazla bir açık dosya tanıtıcısı kullanarak ve diske geçici birleştirilmiş dosya yazmadan parçalı kasaları sanal olarak doğrudan okur.
- **Başsız CLI (`rpm-encrypter-cli`):** Komut satırından parola argümanı geçmeden betiklenebilir şifreleme, çözme, inceleme, anahtar değiştirme, parola üretimi ve Windows kabuk entegrasyonu.
- **Konteyner Dolgusu (Padding) ve Gizli Kasa (Makul İnkâr Edilebilirlik):** Sabit MiB konteyner boyutlarıyla gerçek içerik boyutunu `OsRng` rastgele baytlarıyla gizleyin (`--container-mb` veya GUI Konteyner Boyutu seçicisi) ve isteğe bağlı olarak bağımsız kimlik bilgileriyle ayırt edilemeyen ikinci bir gizli bölme (`--hidden` veya GUI Gizli Kasa paneli) gömün.
- **İsteğe Bağlı Stealth Modu (Şifreli Başlık):** Düz metin `RPMV` başlığı olmadan dış parola/kurtarma slotlarını ve parça çerçevelerini şifreleyerek (`--stealth` veya GUI Şifrele onay kutusu), sabit OWASP Argon2id profili (`64 MiB / 3 / 4`) ile dosyanın uzantısından bağımsız biçimde rastgele baytlardan ayırt edilemez görünmesini sağlayın.
- **İsteğe Bağlı Reed-Solomon Bit-Rot Koruması ve Onarımı:** ~%7 serpiştirilmiş `RS(255, 239)` paritesi (`--reed-solomon` veya GUI Şifrele onay kutusu; Stealth ile karşılıklı dışlayıcıdır) ekleyerek her `16.320` baytlık blokta `512` ardışık bozuk bayta (bir disk sektörüne) kadar sessiz disk hasarını tolere edip şeffaf biçimde onarın; CLI `repair` veya GUI **İncele → Onar (Reed-Solomon)** ile parolasız atomik onarım yapın.
- **Yalnızca Başlıktan Kasa Karşılaştırma (Vault Diff):** İki kasanın doğrulanmış dosya listelerini (eklenen, silinen, değişen, değişmeyen) yalnızca başlıkları açarak GUI **İncele** veya CLI `diff` üzerinden karşılaştırın.
- **Windows Kabuk Entegrasyonu (Kullanıcı Kapsamlı HKCU):** Yönetici hakları gerektirmeden isteğe bağlı sağ tık **"Encrypt with RPM Encrypter"** menüsü ve `.vault` çift tık açılışı.

## Derleme ve Çalıştırma (Saf Rust)

Önkoşullar: Rust kararlı araç zinciri (`rustc` + `cargo`). Linux üzerinde GTK3/X11/OpenGL geliştirme paketlerini (`libgtk-3-dev`, `libxcb-*`, `libxkbcommon-dev`, `libgl1-mesa-dev`) kurun.

```bash
# Testleri ve lint denetimlerini çalıştır
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

# Yerel masaüstü arayüzünü başlat
cargo run --release -p rpm-gui

# Veya target/release/ altında sürüm ikililerini derle
cargo build --release --workspace
```

### Windows sürümünü yerelde paketleme

Proje kökünden PowerShell’de paketleme betiğini çalıştırın. Workspace sürümünü kullanır ve taşınabilir ZIP ile `SHA256SUMS.txt` dosyasını `dist/` dizinine yazar:

```powershell
.\scripts\package-release.ps1
```

### CLI Kullanımı

Parolalar hiçbir zaman CLI bayrağı olarak kabul edilmez; bunun yerine güvenli etkileşimli istemler veya `--password-stdin` / `--recovery-stdin` kullanılır:

```bash
cargo run -p rpm-cli -- encrypt ./klasor --keyfile ./anahtar.key --recovery-out kurtarma.txt
cargo run -p rpm-cli -- encrypt ./klasor --reed-solomon
cargo run -p rpm-cli -- encrypt ./klasor --split-mb 4000
cargo run -p rpm-cli -- encrypt ./klasor --stealth --container-mb 50
cargo run -p rpm-cli -- encrypt ./sahte --container-mb 50 --hidden ./gizli --hidden-keyfile ./gizli.key
cargo run -p rpm-cli -- split ./klasor.vault --part-mb 100
cargo run -p rpm-cli -- join ./klasor.vault.001 -o ./klasor.birlesik.vault
cargo run -p rpm-cli -- repair ./klasor.vault
cargo run -p rpm-cli -- decrypt ./klasor.vault --keyfile ./anahtar.key -o ./cozulen
cargo run -p rpm-cli -- inspect ./klasor.vault --integrity-only --json
cargo run -p rpm-cli -- diff ./kasa-a.vault ./kasa-b.vault
cargo run -p rpm-cli -- rekey ./klasor.vault --keyfile ./anahtar.key
cargo run -p rpm-cli -- password --length 24
cargo run -p rpm-cli -- shell-integration install   # Yalnızca Windows HKCU
```

Tek bir kasadan yalnızca seçili girdileri çıkarmak için `inspect` çıktısındaki yolları kullanın. Her dosya veya klasör için `--only` seçeneğini tekrarlayabilirsiniz. Bu örnek, bir dosyayı ve tüm `fotograflar` klasörünü yeni bir çıktı klasörüne çıkarır:

```bash
cargo run -p rpm-cli -- inspect ./klasor.vault --keyfile ./anahtar.key
mkdir ./secili
cargo run -p rpm-cli -- decrypt ./klasor.vault --keyfile ./anahtar.key -o ./secili --only klasor/notlar.txt --only klasor/fotograflar
```

## Mimari ve Güvenlik

- Mimari genel bakışı ve ikili format düzenleri: [ARCHITECTURE.tr.md](ARCHITECTURE.tr.md) ([English](ARCHITECTURE.md))
- Taviz verilemez tasarım değişmezleri: [docs/DESIGN_INVARIANTS.tr.md](docs/DESIGN_INVARIANTS.tr.md) ([English](docs/DESIGN_INVARIANTS.md))
- Tehdit modeli, takas/işletim sistemi sınırları ve SSD silme uyarıları: [SECURITY.tr.md](SECURITY.tr.md) ([English](SECURITY.md))
- Dört paketi kapsayan kombinasyonel geçerli özellik test kiti: [docs/TEST_KIT.tr.md](docs/TEST_KIT.tr.md) ([English](docs/TEST_KIT.md))

## Lisans

Bu proje GNU Affero General Public License v3.0 (`AGPL-3.0-or-later`) ile lisanslanmıştır — ayrıntılar için [LICENSE](LICENSE) dosyasına bakın.
