# Güvenlik Modeli ve Sınırlar

> [English](SECURITY.md) (varsayılan) · **Türkçe**

RPM Encrypter, Saf Rust ile yazılmış **yalnızca yerel çalışan, tek kullanıcılı bir dosya şifreleme aracıdır** (`Vault Format v5`). Bir servis değildir, sunucusu yoktur ve hiçbir ağ bağlantısı kurmaz. Bu belge neleri koruduğunu ve hangi sınırların sürdüğünü açıklar.

## Tehdit modeli (neler için tasarlandı)

RPM Encrypter; `.vault` dosyalarınızı sonradan ele geçiren birine karşı (kaybolan dizüstü bilgisayar, çalınan disk, paylaşımlı makine veya bulut eşitleme kopyası) **durağan hâldeki dosyaların gizliliğini ve bütünlüğünü** korur:

- **Parçalı Kimlik Doğrulamalı Şifreleme (v5):** Dosya akışları ve şifreli meta veriler, kasa bağlamına, parça sıra numarasına, son parça işaretine ve düz metin uzunluğuna bağlı `1 MiB`’lık **AES-256-GCM** parçalarıyla mühürlenir.
- **Doğrulanmamış Düz Metin Çıkışı Yok:** Her parça açma hattına girmeden veya diske dokunmadan **önce** RAM’de doğrulanır. Kırpma, parça sırasını değiştirme, sona artık bayt ekleme veya tek bit bozulması anında hata verir.
- **Sıfır Geçici Düz Metin Arşivi ve Atomik Stage-and-Swap:** Paketleme ve açma, diske geçici düz metin arşivi yazmadan sınırlı bir bellek içi boru (pipe) üzerinden doğrudan AEAD akışına akar. Çözme işlemi; tar-slip, symlink/hardlink, yol derinliği (`128`), dosya sayısı (`500.000`) ve açılmış boyut (`64 GiB`) sınırlarıyla korunan gizli kardeş hazırlık klasörüne (`.rpm_unpack_*.part`) çıkarır ve yalnızca son parça doğrulandıktan sonra dosyaları atomik olarak hedefe taşır.
- **Anahtar Türetme ve Keyfile Bağlama:** Parolalar **Argon2id** (varsayılan `64 MiB`, `3` yineleme, `4` şerit) ile güçlendirilir ve isteğe bağlı olarak ikinci faktör bir keyfile’a HKDF-SHA256 üzerinden bağlanır.
- **Kesin Bellek Sıfırlama:** Gizli anahtarlar, referans sayaçlı işletim sistemi bellek kilitlemesiyle (Windows’ta `VirtualLock`, Unix’te `mlock`) mümkün olan en iyi çabayla korunan sabit 32 bayt hizalı heap adreslerinde tutulur. Keyfile özetleri, parolalar, kurtarma cümleleri ve düz metin tamponları `zeroize` / `Zeroizing` korumalarıyla sarmalanır ve erken hata yollarında bile kesin biçimde sıfırlanır.

## Neleri KORUMAZ

### Güvenli silme (secure wipe) garanti değil, en iyi çabadır (best-effort)

Şifreleme sonrası kaynak dosyaların üzerine yazmak (`--wipe` veya onay kutusu), modern depolama birimlerinde verinin kurtarılamayacağını **garanti etmez**:

- **SSD / flash diskler:** Aşınma dengeleme (wear-leveling), TRIM ve yedek blok ayırma nedeniyle denetleyici mevcut flash hücrelerinin üzerine yerinden yazmak yerine yeni bloklara yazar.
- **Dosya sistemleri ve önbellekler:** Copy-on-write dosya sistemleri (APFS, Btrfs, ZFS, ReFS), günlükleme (journaling), anlık görüntüler (snapshots), küçük resimler ve yedekler eski kopyaları tutabilir.

Yüksek hassasiyetli imha gereksinimlerinde **en baştan tam disk şifrelemesi** kullanın veya ortamı fiziksel olarak imha edin.

### İşletim sistemi belleği, takas (swap), hazırda bekletme ve GPU/IME tamponları

Saf Rust, Python/Dart çöp toplayıcısından kaynaklı dize kalıntılarını önleyip sırları kesin biçimde sıfırlasa (`zeroize` + best-effort `VirtualLock`/`mlock`) bile:

- İşletim sistemi sayfa kilitleme sınırları (`RLIMIT_MEMLOCK` / çalışma kümesi kotaları) yük altında kilitlemenin kilitlenmemiş belleğe düşmesine yol açabilir.
- Windows hazırda bekletme (`hiberfil.sys`), çökme dökümleri, GPU/OS metin çizim önbellekleri (`egui`) veya IME geçmişi uygulama kontrolü dışındaki geçici arayüz girdilerini tutabilir.
- RAM-içi önizleme (`İncele → Önizle`) girdileri yalnızca sıfırlanan bellek tamponlarına alır ve pencere kapatma, `Esc`, sekme değişimi veya kasa değişiminde tamponları/dokuları temizler; ancak işletim sistemi takas/hazırda bekletme alanı ve GPU sürücüsü doku tahsisleri uygulama kontrolü dışındadır.
- Tehdit modeliniz uyku/hazırda bekletme sonrası fiziksel bellek adli incelemesini içeriyorsa işletim sistemi tam disk şifrelemesini açın ve hazırda bekletmeyi kapatın.

### Diğer sınırlar

- **Kayıp kimlik bilgisi = kayıp veri.** Parolanızı, bağlı keyfile’ınızı veya 24 kelimelik kurtarma cümlenizi kaybederseniz kasa açılamaz.
- **Çevrimdışı kaba kuvvet (brute-force).** `.vault` dosyanızın bir kopyasını elinde bulunduran herkes Argon2id ayarlarınızın hızıyla sınırlı olacak şekilde çevrimdışı parola denemesi yapabilir. Güçlü bir parola seçin (veya yüksek entropili bir keyfile bağlayın).
- **v4 geriye dönük uyumluluğu yok.** Vault Format v5, eski Python v4 arşivlerinin yerini bilinçli olarak almıştır (eski v4 kod tabanı önceki Git geçmişinde korunmaktadır).
- **Ana makine güveni.** RPM Encrypter bilgisayarınızda çalışan zararlı yazılımlara, tuş kaydedicilere (keylogger), ele geçirilmiş çekirdeklere veya fiziksel donanım müdahalelerine karşı koruma sağlayamaz.

## Konteyner Dolgusu ve Gizli Kasa (Makul İnkâr Edilebilirlik)

Tasarım; dolgulu bir konteynerin çevrimdışı bir kopyasına sahip olan ancak gizli kasa kimlik bilgilerine sahip olmayan bir gözlemciye karşı geliştirilmiştir. Sıradan dolgulu konteynerler ile gizli bölme içeren konteynerler birebir aynı açık başlık düzenini (`container_size` ve `container_salt`) kullanır ve gizli kasa bayrağı içermez. Eşit boyuttaki konteynerlerde bayt incelemesi şifreli gizli meta veriyi, maskeli çerçeve öneklerini veya gizli parçaları `OsRng` rastgele dolgusundan ayırt edemez.

Dolgulu konteynerler her iki biçimde de `rekey` işlemini reddederek komut davranışının gizli bölme varlığını sızdırmasını engeller. `.vault` bayt doğrulamasının dışındaki doğal operasyonel sınırlar olarak; zaman içinde alınan birden fazla konteyner anlık görüntüsü farkları ortaya koyabilir ve işletim sistemi son kullanılan dosya listeleri, küçük resimler, yedekler, takas/hazırda bekletme dosyaları veya kalan SSD blokları etkinliği dolaylı yoldan gösterebilir.

## Stealth Modu (Şifreli Başlık / 1. Katman İnkâr Edilebilirlik)

Stealth Modu düz metin `RPMV` imzasını ve JSON başlığı tamamen kaldırır: `[0..32]` baytları rastgele bir tuz içerir, ardından sabit 108 baytlık AES-GCM parola ve kurtarma slotları (kurtarma entropisi verilmezse tekdüze rastgele gürültü), şifreli meta veri, HKDF maskeli 5 baytlık çerçeve önekleri ve şifreli veri parçaları gelir. Dolgusuz, dolgulu ve gizli Stealth dosyaları sabit bir OWASP Argon2id taban profili (`64 MiB`, `3` yineleme, `4` şerit) kullanır; yanlış/eksik parola veya keyfile durumunda tekdüze biçimde `AuthenticationFailed` döner, `rekey` işlemini `UnsupportedOperation` ile reddeder ve parolasız bütünlük kontrollerinde yalnızca dosya boyutu + SHA-256 bildirerek kimlik bilgisi olmadan normal dosyalar ile Stealth kasaların birebir aynı görünmesini sağlar. Stealth oluşturma sırasında diskte `.rpm_tmp_` kardeş geçici dosya izi bırakmamak için Stealth doğrudan yeni hedef dosyaya (`create_new`) yazar ve hata döndüğünde kısmi çıktıyı siler — bunun açık bir ödünleşimi olarak, yazma ortasında ani elektrik kesintisi veya `SIGKILL` hedef yolda kısmi şifreli bir dosya bırakabilir.

## Reed-Solomon Bit-Rot Koruması

İsteğe bağlı Reed-Solomon sarmalaması 64 yollu serpiştirmeyle (`16.320` baytlık blok başına `15.292` iç bayt) Saf Rust `#![forbid(unsafe_code)]` GF(2⁸) `RS(255, 239)` ve üçlü CRC32 korumalı `RPMR` dış başlığı kullanır:

- **Fiziksel kurtarma sınırı:** Her `16.320` baytlık blokta `512` ardışık bozuk bayta (bir disk sektörü) kadar onarır ve üçlü dış başlık ile blok-0 yapısal doğrulaması sayesinde sektör-0’ın tamamen silinmesini tolere eder. Herhangi bir 255 baytlık serpiştirilmiş kod sözcüğünde `8` bozuk sembolü aşan hasarların onarımı garanti edilmez ve başka bir kod sözcüğüne çözülebilir (ancak AES-256-GCM bunu reddeder).
- **Kimlik doğrulama tamamen kriptografik kalır:** Reed-Solomon paritesi kaza sonucu oluşan medya bozulmasını çözmeden *önce* onarır ve şifreli metni asla doğrulamaz. Şifreli metni değiştirip geçerli RS parite baytlarını yeniden hesaplayan bir saldırgan AES-256-GCM tarafından sıfır düz metin çıkışıyla reddedilir.
- **Stealth Modu ile uyumsuzluk:** Şifresiz parite bloklarındaki sıfır sendromlar RS konteynerlerini tekdüze rastgele baytlardan ayırt edilebilir kıldığı için Reed-Solomon, Stealth Modu ile kesin olarak karşılıklı dışlayıcıdır (`--stealth` + `--reed-solomon` reddedilir). Dolgulu/RS zarfları ayrıca yerinde `rekey` işlemini reddeder (`UnsupportedOperation`).

## Güvenlik açığı bildirme

Bir güvenlik sorunu bulursanız lütfen hassas istismar ayrıntılarını herkese açık yayımlamadan bir issue açın veya proje bakıcısıyla iletişime geçin.
