# Değişiklik Günlüğü

> [English](CHANGELOG.md) (varsayılan) · **Türkçe**

## v4.7.0

- **Çok Çekirdekli Sınırlı Bellekli Paralel AEAD ve Reed-Solomon Boru Hattı (`rpm-core`, `rpm-storage`, CLI, GUI):** Vault Format v5’te hiçbir değişiklik (`INV-01`) ve yeni harici bağımlılık olmadan, `#![forbid(unsafe_code)]` altında `8 MiB` sabit tampon bütçeli kayan pencereli paralel AES-256-GCM parça boru hattı (`pipeline.rs`) ve talep üzerine ölçeklenen paralel `RS(255, 239)` dilim kodlayıcı/okuyucu/tarayıcı (`rs.rs`) eklendi. Doğrulanmamış düz metin bırakmayan sıralı parça çıkışı (`INV-02`), deterministik `Zeroizing` bellek temizliği (`INV-07`), tek parça veya `--threads 1` akışlarda sıfır iş parçacığı maliyeti, kısmi işçi hatası/panik koruması ve gerçek OS `io::Error` kodu korunumu sağlanır. CLI’da `encrypt`, `decrypt`, `inspect`, `repair` ve `diff` komutlarına `--threads <0..=64>`, GUI **Ayarlar** sekmesine ise kalıcı **AEAD / Reed-Solomon İş Parçacığı** seçicisi (`pipeline_threads`, `0` = otomatik) eklendi.
- **Çevrimdışı Yazdırılabilir Kurtarma Kartı (`.html`) (`rpm-storage`, CLI, GUI):** Katı CSP (`default-src 'none'; style-src 'unsafe-inline';`), sıfır JavaScript, sıfır harici URL/yazı tipi, önceden BIP-39 doğrulaması, tam HTML kaçışı, `Zeroizing<String>` tamponu, atomik yazım (Unix’te `0o600`) ve gizli bölme bilgisini ya da `keyfile_hash` değerini asla içermeyen `INV-06` makul inkâr korumasıyla kendi kendine yeten A4/Letter baskı uyumlu HTML kurtarma kartı (`recovery_sheet.rs`) eklendi. CLI’da `encrypt --recovery-sheet <YOL> [--recovery-sheet-lang <en|tr>]` (`--wipe` çakışma korumalı) ve bağımsız `recovery-sheet -o <YOL> [--vault-name <AD>] [--has-keyfile] [--lang <en|tr>] [--recovery-stdin]` alt komutu ile GUI 24 kelimelik onay penceresinde **Yazdırılabilir Kart Kaydet (.html)...** düğmesi olarak entegre edildi.

## v4.6.0

- **Parçalı Kasa Bölme / Birleştirme ve Sıfır Geçici Dosyalı Sanal Okuyucu (`rpm-storage`, CLI, GUI):** Vault Format v5’te hiçbir değişiklik ve yeni harici bağımlılık olmadan akış tabanlı çok parçalı kasa bölme (`.vault.001`, `.vault.002`, ...) eklendi. CLI’da `encrypt --split-mb <MiB>`, bağımsız `split --part-mb <MiB>` ve `join` alt komutları; GUI’de **Parçalı Bölme** hazır seçenekleri (`25 / 100 / 500 / 2000 / 4000 MiB (FAT32 Güvenli)` ve özel MiB), kayıtlı **Şifreleme Profili** kalıcılığı (`split_part_mib`), ön kontrol parça sayısı tahmini, sürükle-bırak `.001/.002` tekilleştirmesi ve **İncele** altında açılır **Parçalı Kasa Böl / Birleştir** aracı desteklenir. `decrypt`, seçici çıkarma, RAM önizleme, `inspect`, `diff`, `rekey` ve Reed-Solomon `repair`; aynı anda tek dosya tanıtıcısı kullanan sanal `Read + Seek` okuyucu (`SplitVolumeReader`) ile diske geçici birleştirilmiş dosya yazmadan parçalı kasaları doğrudan okur.
- **Kasa Gezgini Klasör Ağacı ve Filtreler (GUI İncele):** Düz manifest listesi; üç durumlu klasör onay kutuları, özyinelemeli dosya/bayt toplamları, **Tümünü Aç / Tümünü Kapat**, sabit genişlikli rozetli dosya türü filtreleri (`Metin / Kod`, `Görsel`, `Arşiv`, `Medya / PDF`, `Diğer / İkili`) ve boyut filtreleri (`<= 16 MiB Önizlenebilir`, `< 1 MiB`, `1–16 MiB`, `> 16 MiB`) içeren etkileşimli **Klasör Ağacı / Düz Liste** gezginiyle değiştirildi.
- **Gelişmiş RAM-İçi Önizleme (Metin Arama, Görsel Yakınlaştırma/Döndürme ve Hex Görüntüleyici):** Sıfır-disk RAM önizleme penceresi; satır hizalı UTF-8 sayfalama, açılır satır numaraları, eşleşme vurgulama ve sayfalar arası gezinme sunan Unicode/Türkçe uyumlu `Ctrl+F` araması, kapatmada pikselleri temizleyen kayıpsız `90°` sağa/sola görsel döndürme ve yakınlaştırma (`%25–%400` / `%100` / `Sığdır`) ile ikili dosyalar için sayfalı `4 KiB` salt okunur Hex + ASCII görüntüleyici ile güncellendi.
- **Depolama Katmanı Sertleştirme ve Denetim Düzeltmeleri:** Çok parçalı kaydetme iki fazlı yedek/geri alma takası ile sertleştirildi (`ReadOnly` ve kilitli dosya koruması); yalnızca o anki çalıştırmaya özgü `OutputExclusion` ile Stealth dışı geçici dosyaların kaynak klasöre paketlenmesi ve Stealth modda önceden var olan `<ad>.NNN` kullanıcı dosyalarının sessizce atlanması engellendi; `join` ve `repair -o` için split seti üzerine yazma korumaları, NTFS ile uyumlu Unicode harf eşleştirme (`Ş/ş`, `Ö/ö`, `Ü/ü`, `Ç/ç`, `Ğ/ğ`), `rekey_stream` içinde tam parça çerçeve + `final_flag == 1` + EOF doğrulaması, `O(N)` split tekilleştirme, 255 bayt sınırı için kısa `.rpm_tmp_` adları ve CLI ile eş GUI `secure_wipe` / gizli bölme çakışma korumaları eklendi.

## v4.5.0

- **Pano-Güvenli Hareketsizlikte Otomatik Kilit ve Manuel Panik Temizleme (`Ctrl+L`):** **Ayarlar**’da yapılandırılabilir hareketsizlik süresi (`Kapalı`, `1`, `5`, `15`, `30` dk; varsayılan `5` dk) ve kenar çubuğunda **Oturumu Temizle (`Ctrl+L`)** eklendi; uygulama içi tüm parolaları, kurtarma cümlelerini, RAM önizlemelerini, yüklü manifestleri, Vault Diff çıktılarını, üretilen parolaları, işlem günlüklerini, işlem sonrası banner’ları ve bekleyen kuyruk bilgilerini sıfırlarken **işletim sistemi panosuna kesinlikle dokunmaz**. Aktif aktarımlar (önizleme dışı) sayacı otomatik erteler.
- **Kayıtlı Şifreleme Profilleri (Hazır Şablonlar ve Özel Profiller):** 3 hazır profil (**Günlük Yedek**, **Uzun Ömürlü Arşiv (RS)**, **Maksimum Gizlilik (Stealth)**) ve `config.json` içinde sıfır gizli bilgiyle saklanan en fazla 32 kullanıcı profili eklendi; Stealth/Reed-Solomon karşılıklı dışlaması korunur ve **Gizli Kasa** etkinken `Otomatik` konteynerler otomatik olarak `50 MiB`’a çekilir.
- **Ön Kontrol Boyut, Reed-Solomon Ek Yükü ve Konteyner Sığma Tahmincisi:** Şifreleme başlamadan önce **Şifrele** sekmesinde arka plan kaynak boyutu taraması (`packager.rs` ile uyumlu sembolik bağ atlamalı ve iptal edilebilir), kesin `RS(255, 239)` parite hesabı (`~%6,7`) ve canlı konteyner sığma göstergeleri (**Sığar**, **Sıkıştırmaya Bağlı** veya minimum MiB önerili **Sığmaz**) eklendi.
- **İşlem Sonrası Hızlı Aksiyonlar, Odak Dışı Uyarı ve Sıfırlamalı Toplu İş Kuyruğu:** Alt şeride tek tıkla **Klasörde Göster** ve **Şimdi Doğrula**, pencere odak dışındayken isteğe bağlı görev çubuğu uyarısı ve yeniden sıralama/duraklatma/devam/iptal-duraklatma ile sansürlü hata ayıklama çıktısı sunan sıralı sıfırlamalı iş kuyruğu (**Kuyruğa Ekle**) eklendi.
- **Önceden Kısıt Netliği, Güvenilirlik Sertleştirme ve Güvenlik Bakımı:** Çakışan Stealth/RS anahtarları ipucuyla pasifleştirildi; Re-Key, SSD silme, `.vault` dışı Stealth bırakma ve `16 MiB` önizleme sınırı notları eklendi; gzip CRC32 kuyruk boşaltma ve platformlar arası tar yol temizliği güçlendirildi; `url` `2.5.9`’a güncellendi (`RUSTSEC-2026-0592`); önizleme iptal/değişim kilidi, Windows yazı tipi yedeği ve Stealth tuz `RPMR` çakışma kaçınması düzeltildi; donmuş `v4.4.0` altın kasa testleri, deterministik fuzzing ve tepe-RAM/tek-geçiş I/O koruma testleri eklendi.

## v4.4.0

- **İsteğe Bağlı Reed-Solomon Bit-Rot Koruması (`RS(255, 239)`):** Standart, dolgulu ve gizli Vault Format v5 kasaları için CLI’da `--reed-solomon` ve GUI **Şifrele**’de **Reed-Solomon Bit-Rot Koruması (~%7 parite)** eklendi. 64 yollu bayt serpiştirmesi (`15.292 B` iç veri → `16.320 B` akış bloğu) ve üçlü CRC32 korumalı `RPMR` dış başlığıyla Saf Rust (`#![forbid(unsafe_code)]`, sıfır yeni bağımlılık) olarak geliştirildi; blok başına `512` ardışık bozuk bayta (bir disk sektörüne) kadar onarır.
- **Şeffaf Kurtarma ve Parolasız Atomik Onarım:** `decrypt`, seçici çıkarma, RAM-içi önizleme, `inspect`, `diff` ve bütünlük kontrolleri blokları şeffaf biçimde çözüp onarılan baytları sayar. `rpm-encrypter-cli repair` (yerinde veya `-o <YOL>`) ve GUI **İncele → Onar (Reed-Solomon)** (`repair_vault_v5`) eklendi.
- **Kriptografik Sınırlar ve UX İyileştirmeleri:** RS paritesi Stealth Modu ile kesin olarak dışlayıcıdır, kaza sonucu oluşan disk hasarını AES-256-GCM doğrulamasından *önce* onarır (geçerli parite kurcalanmış veriyi asla doğrulamaz), dış sahte bloklar onarılamayacak kadar hasarlıyken bile sağlam gizli bölme kurtarmasını korur ve yerinde `rekey` işlemini nötr `CryptoError::UnsupportedOperation` ile reddeder.

## v4.3.0

- **İsteğe Bağlı Stealth Modu (Şifreli Dış Başlık):** Dolgusuz, dolgulu ve gizli kasalarda CLI `--stealth` ve GUI **Stealth Modu (Şifreli Başlık)** eklendi. Düz metin `RPMV` imzası ve JSON başlık kaldırılarak sabit boyutlu dış parola/kurtarma slotları ve HKDF XOR maskeli parça çerçeveleri sabit OWASP Argon2id profiliyle (`64 MiB / 3 yineleme / 4 şerit`) şifrelenir.
- **Ayırt Edilemeyen Hatalar ve Yalnızca Özet Bütünlük Kontrolü:** Stealth kasalarda yanlış parola veya eksik/yanlış keyfile tekdüze biçimde `AuthenticationFailed` döner (`KeyfileRequired` sızdırmaz); `RPMV` taşımayan dosyalarda parolasız denetim yalnızca boyut ve SHA-256 (`sha256_only: true`) döndürür ve `rekey` reddedilir.
- **Stealth Depolama ve UX İyileştirmeleri:** Stealth şifreleme doğrudan yeni hedefe (`create_new`) akar ve seçili klasör içindeki çıktı yolunu otomatik dışlar; GUI dosya seçicileri tüm uzantıları kabul eder (`All Files`).

## v4.2.0

- **Yalnızca RAM İçi Sıfır-Disk Önizleme:** Standart, dolgulu ve gizli bölmelerde diske geçici dosya yazmadan `16 MiB`’a kadar dosya önizlemesi (`extract_entry_to_memory_v5` ve GUI **İncele → Önizle**) eklendi; tüm bölme AEAD doğrulaması bitmeden gösterilmez, sayfalı UTF-8 metin ve `PNG/JPEG/WebP/GIF/BMP` görselleri desteklenir ve pencere kapatma, `Esc`, sekme veya kasa değişiminde bellek sıfırlanır.
- **Nötr Re-Key Hata Raporlaması:** Sabit boyutlu konteynerlerde kullanılamayan `rekey` işlemi dolgu varlığını sızdırmayan nötr yerelleştirilmiş hata döndürür.

## v4.1.0

- **Konteyner Dolgusu:** Sabit MiB konteyner boyutları (`--container-mb` ve GUI **Konteyner Boyutu (Padding)**) gerçek arşiv boyutunu `OsRng` rastgele baytlarıyla gizler.
- **Gizli Kasa (Makul İnkâr Edilebilirlik):** Herhangi bir sabit boyutlu konteyner içine sonda yer alan 108 baytlık AES-GCM mini başlık ve maskeli çerçevelerle ikinci bir gizli bölme (`--hidden`, `--hidden-keyfile`, `--hidden-no-compress`) gömülebilir.
- **Bölme Farkındalıklı İşlemler ve Belge Temizliği:** `decrypt`, seçici çıkarma, `inspect` ve `diff` girilen kimlik bilgisine göre dış/gizli bölmeyi seçer; dolgulu kasalarda `rekey` kapatılır, `24` kelimelik kurtarma cümlesi yalnızca dış kasayı açar; iki dilli belgeler eklendi ve eski Python `legacy/` dizini Git takibinden çıkarıldı.

## v4.0.2

- **Vault Diff:** İki kasa başlığındaki doğrulanmış dosya listelerini boyut ve zaman damgasıyla karşılaştırır (`diff` komutu ve GUI **İncele**).
- Masaüstü arayüzü `eframe 0.31`’den `0.37`’ye yükseltildi ve `quick-xml 0.30.0` istisnası kaldırıldı.
- Ayarlar ekranına Argon2id yineleme/paralellik ayarları ve arayüz ölçeği (`%80–%150`) eklendi.
- Parola Üretici’ye büyük/küçük harf, rakam, sembol ve karıştırılabilir karakter filtresi eklendi.

## v4.0.1

- GUI ve CLI’da şifreleme/çözme sırasında canlı aktarım hızı ve tahmini kalan süre (ETA); CLI’da `--progress auto|always|never` bayrağı eklendi.
- Seçici çıkarmada atlanan girdiler de arşiv açma boyut sınırına sayılır.
- CI’a `cargo-deny` denetimi ve GitHub Release paketlerine imzalı build provenance doğrulaması eklendi.
- Taşınabilir Windows ZIP paketi için WinGet manifest üreteci ile bozuk/sınır girdiler için dayanıklılık testleri eklendi.

## v4.0.0

- **Saf Rust Göçü:** Masaüstü uygulaması ve CLI ortak Saf Rust çekirdeğine taşındı; Vault Format v5 bilinçli olarak v4 ile geriye dönük uyumlu değildir (eski Python/Flet uygulaması önceki Git geçmişinde arşivlenmiştir).
- **Vault Format v5:** `1 MiB` AES-256-GCM parçalarıyla akış şifreleme ve kimlik doğrulama.
- **Masaüstü Uygulaması:** Türkçe/İngilizce arayüz, sürükle-bırak ve Windows sürümünde uygulama simgesi/ürün meta verisi gömme.
- **Seçici Çıkarma ve Daha Güvenli Açma:** Tar-bomb ve yol atlama koruyuculu stage-and-swap geçici dizin doğrulaması.
- **Taşınabilir Sürümler:** Windows ZIP, Linux `.tar.gz` ve `SHA256SUMS.txt` paketleri ([paketleme betiği](scripts/package-release.ps1)).
