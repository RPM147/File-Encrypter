# RPM Encrypter — Mimari ve Uyumluluk Politikası

> [English](ARCHITECTURE.md) (varsayılan) · **Türkçe** · Tasarım değişmezleri ve taviz verilemez mühendislik kuralları: [docs/DESIGN_INVARIANTS.tr.md](docs/DESIGN_INVARIANTS.tr.md) ([English](docs/DESIGN_INVARIANTS.md))

## Paket Yerleşimi

```text
Cargo.toml                  # Saf-Rust workspace manifesti (unsafe RS/kripto sarmalayıcı yok)
crates/
  rpm-core/                 # Vault Format v5 (Parçalı AEAD, Argon2id, HKDF, BIP-39, Gizli RPMH, Stealth, RS RPMR, Diff, Zeroize/VirtualLock/mlock)
  rpm-storage/              # Sınırlı sıfır-geçici-dosya borusu, tar+gzip paketleyici, atomik I/O, RAM-içi önizleme, güvenli silici, ayarlar, HKCU kabuk entegrasyonu
  rpm-cli/                  # Başsız CLI ikilisi (rpm-encrypter-cli)
  rpm-gui/                  # OS sürükle-bırak ve RAM önizlemeli yerel eframe/egui masaüstü GUI ikilisi (rpm-encrypter)
```

## Bağımlılık Kuralları (Çevrimsiz)

1. **`rpm-core`** yalnızca saf-Rust kripto/serileştirme paketlerine (`aes-gcm`, `argon2`, `hkdf`, `sha2`, `bip39`, `base64`, `zeroize`, `serde`, `serde_json`, `thiserror`, `rand` ve Win32/Unix bellek kilitleme bağlayıcıları) dayanır. `rs.rs` gibi saf-Rust protokol/FEC modülleri `#![forbid(unsafe_code)]` uygular. Hiçbir zaman arayüz, arşiv veya kayıt defteri işlemi yapmaz.
2. **`rpm-storage`** `rpm-core`’a bağımlıdır ve akış tabanlı tar/deflate paketleme, sınırlı açma, bellekte sınırlı boru aktarımı, çökme güvenli atomik yazma, parçalı kasa (split/join) sanal akışı, RAM-içi girdi önizlemesi, en iyi çabayla silme, ayar kalıcılığı ve Windows HKCU kabuk entegrasyonunu uygular.
3. **`rpm-cli`** yalnızca `rpm-core` ve `rpm-storage`’a bağımlıdır (sıfır GUI paketi).
4. **`rpm-gui`**, `eframe`/`egui` + `rfd` + `zxcvbn` bileşenlerini `rpm-core` ve `rpm-storage`’ı süren arka plan iş parçacıklarına bağlar.

## Kilitli Vault Format v5 İkili Akış (Wire) Özellikleri

Vault Format **v5**, `VAULT_VERSION = 5` olarak dondurulmuştur:

### 1. Standart ve Dolgulu Dış Kasa (`RPMV`)

```text
+-------------------+-----------+-----------------------------------------------+
| Konum / Alan      | Boyut     | Açıklama                                      |
+-------------------+-----------+-----------------------------------------------+
| Magic             | 4 bayt    | "RPMV"                                        |
| Version           | 1 bayt    | 0x05                                          |
| HeaderLength      | 4 bayt    | HeaderJSON u32 BE uzunluğu (1..=1 MiB)        |
| HeaderJSON        | N bayt    | UTF-8 JSON VaultHeader                        |
| EncryptedMetadata | M bayt    | AES-256-GCM(DEK, meta_nonce, JSON, AAD=CTX)   |
| ChunkFrames[0..k] | Değişken  | final_flag == 1 olana dek tekrarlayan parçalar|
| RandomPadding     | Değişken  | container_size'a kadar OsRng (dolguluysa)     |
+-------------------+-----------+-----------------------------------------------+
```

- **Bağlam Türetme (`payload_context`):**
  `SHA-256("RPMV5-CTX" || version || len(cipher) || cipher || chunk_size || compressed_flag || vault_id [|| container_size || container_salt])` her değişmez arşiv parametresini (ve isteğe bağlı konteyner geometrisini) meta veriye, anahtar slotlarına, `7` baytlık HKDF akış nonce önekine (`"rpm-v5-stream-nonce"`) ve her parça AAD’sine bağlar.
  (`VaultHeader.flags` içindeki `FLAG_HAS_KEYFILE`, O(1) `rekey_stream` için değiştirilebilir kalır ve `password_slot_aad` tarafından kimlik doğrulanır.)
- **Parça Çerçevesi Düzeni (varsayılan `CHUNK_SIZE = 1 MiB`, izin verilen aralık `[16 KiB, 16 MiB]`):**
  `plain_len (u32 BE) || final_flag (1 bayt: 0 veya 1) || AES-256-GCM(DEK, nonce_prefix || chunk_idx || final_flag, plaintext, AAD="RPMV5-CHUNK" || payload_ctx || chunk_idx || final_flag || plain_len)`.
  Son parça (`final_flag == 1`) hariç tüm parçalar boş olmamalıdır; son parça dolgusuz kasalarda EOF’ta, sabit boyutlu `container_size` kasalarında (`[64 KiB, 64 GiB]`) ise sınırlı rastgele dolgu içinde sonlanır.

### 2. Konteyner Dolgusu ve Gizli Bölme (`RPMH`)

- Standart dolgulu konteynerler (`--container-mb`) ile gizli kasa konteynerleri birebir aynı herkese açık dış `VaultHeader` düzenini (`container_size` + `container_salt`, sıfır gizli bölme bayrağı) paylaşır.
- Sabit konteyner geometrisi içinde isteğe bağlı ikinci gizli bölme, `RPMH` şifreli veri çerçevelerini (HKDF maskeli 5 baytlık parça çerçeve önekleriyle), ardından şifreli meta veriyi ve konteyner sonunda `108` baytlık trailing AES-256-GCM mini başlığı (`12` bayt nonce + `80` bayt paketlenmiş veri + `16` bayt doğrulama etiketi) yazar. Kullanılmayan tüm alan `OsRng` rastgele baytlarıyla doldurulur.

### 3. İsteğe Bağlı Stealth Modu (Şifreli Başlık)

```text
+-------------------+-----------+-----------------------------------------------+
| Konum / Alan      | Boyut     | Açıklama                                      |
+-------------------+-----------+-----------------------------------------------+
| OuterSalt         | 32 bayt   | Rastgele Argon2id / kurtarma tuzu             |
| PasswordSlot      | 108 bayt  | AES-256-GCM(KEK, nonce, 80B slot, AAD)        |
| RecoverySlot      | 108 bayt  | AES-256-GCM slotu (veya 108B OsRng rastgele)  |
| EncryptedMetadata | Değişken  | AES-256-GCM(DEK, meta_nonce, JSON, AAD=CTX)   |
| MaskedChunkFrames | Değişken  | HKDF maskeli 5 bayt çerçeve önekleri + AEAD   |
| RandomPadding     | Değişken  | İsteğe bağlı OsRng + gizli bölme sonu         |
+-------------------+-----------+-----------------------------------------------+
```

- Dolgusuz, dolgulu ve gizli Stealth kasalar **sıfır** doğrulanmamış imza dizgesi, uzunluk alanı veya KDF ayarı taşır. Tüm Stealth kasalar sabit OWASP Argon2id taban profilini (`64 MiB`, `3` yineleme, `4` şerit) zorunlu kılar, yanlış parola/keyfile durumunda tekdüze biçimde `AuthenticationFailed` döner, `rekey` işlemini (`UnsupportedOperation`) reddeder, parolasız denetimlerde yalnızca SHA-256 + dosya boyutu bildirir ve doğrudan `create_new` ile yazar (asla `.rpm_tmp_*` kardeş dosyaları üzerinden yazmaz).

### 4. İsteğe Bağlı Reed-Solomon Bit-Rot Sarmalayıcısı (`RPMR`)

```text
+-------------------+-----------+-----------------------------------------------+
| Konum / Alan      | Boyut     | Açıklama                                      |
+-------------------+-----------+-----------------------------------------------+
| PrefixHeader      | 48 bayt   | 3x 16 bayt kopya ("RPMR\x01\x10\x40..." + CRC32)|
| RSBlocks[0..n]    | n*16.320B | 64 yollu serpiştirilmiş GF(2^8) RS(255, 239)  |
+-------------------+-----------+-----------------------------------------------+
```

- Her `16.320` baytlık akış bloğu `64` adet kısaltılmış sistematik `RS(255, 239)` kod sözcüğünü (`15.292` iç veri baytı + `4` bayt iç uzunluk + `1.024` parite baytı) serpiştirir; blok başına **`512` ardışık bozuk bayta** (bir disk sektörü) kadar deterministik olarak onarım yaparken üçlü CRC32 başlığı ve blok-0 `RPMV` doğrulaması sayesinde sektör-0 hasarını da tolere eder.
- **Stealth Modu ile kesin olarak karşılıklı dışlayıcıdır:** RS paritesi sıfır-sendrom matematiksel yapısı bırakır ve tekdüze rastgele Stealth konteynerleriyle bir arada bulunamaz.
- **Kimlik doğrulama tamamen kriptografik kalır:** RS, iç çözmeden önce fiziksel medya bozulmasını onarır; özgünlüğe her zaman iç AES-256-GCM etiketleri karar verir.

### 5. Yalnızca RAM İçi Sıfır-Disk Önizleme

- `rpm-storage::preview`, çözülen baytları doğrulanmış parça akışından doğrudan tar/gzip üzerinden sıfırlanan RAM’e (`DEFAULT_PREVIEW_MAX_BYTES = 16 MiB` varsayılan sınırı) geçici dosya olmadan akıtır.
- `rpm-gui`, çözülmüş önizleme durumunu **tüm bölme akışı** son parça AEAD doğrulamasını tamamlayana kadar kapalı tutar ve `Esc`, kapatma, sekme değişimi veya kasa değişiminde tamponları/dokuları sıfırlar.

## Temiz Sayfa / v4 Geriye Dönük Uyumsuzluk Olmaması Politikası

RPM Encrypter, Python + Flet’ten **Vault Format v5** ile **Saf Rust**’a geçmiştir:

- Eski Python + Flet kodu (`Vault Format v4`) önceki Git geçmişinde korunmaktadır; artık izlenmez veya derlenmez.
- Vault Format **v5 (`Parçalı AES-256-GCM`)**, v4’ün 32 GiB veri sınırını ve doğrulanmamış geçici düz metin arşivi kısıtlarını ortadan kaldırmak amacıyla v4 arşivleriyle uyumluluğu bilinçli olarak sonlandırmıştır.
- **v5 (`v4.4.0+`)** içinde ise sürümler arası geriye dönük uyumluluk kesin biçimde korunur (bkz. [docs/DESIGN_INVARIANTS.tr.md](docs/DESIGN_INVARIANTS.tr.md) içindeki `INV-01`).

## İlgili Belgeler

- [SECURITY.tr.md](SECURITY.tr.md) ([English](SECURITY.md)) — Tehdit modeli, bellek kilitleme, SSD/takas uyarıları ve özellik garantileri
- [docs/DESIGN_INVARIANTS.tr.md](docs/DESIGN_INVARIANTS.tr.md) ([English](docs/DESIGN_INVARIANTS.md)) — Taviz verilemez mimari ve güvenlik değişmezleri
- [docs/TEST_KIT.tr.md](docs/TEST_KIT.tr.md) ([English](docs/TEST_KIT.md)) — Dört paketteki kombinasyonel geçerli özellik matrisi
