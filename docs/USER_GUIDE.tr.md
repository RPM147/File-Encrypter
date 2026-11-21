# RPM Encrypter kullanım kılavuzu

> English: [USER_GUIDE.md](USER_GUIDE.md)

RPM Encrypter, dosya ve klasörlerinizi bilgisayarınızda şifreleyip `.vault` uzantılı bir kasaya kaydeder. Bu kılavuz Vault Format v5 içindir.

## Uygulamayı açma

Windows’ta indirdiğiniz ZIP paketini bir klasöre çıkarın ve `rpm-encrypter.exe` dosyasına çift tıklayın. Linux’ta `.tar.gz` paketini çıkarın, o klasörde bir terminal açın ve `./rpm-encrypter` komutunu çalıştırın.

Uygulama varsayılan olarak Türkçe arayüzle açılır; sol menünün altından veya **Ayarlar** sekmesinden dili (`TR / EN`) ve temayı (**Açık / Koyu**) değiştirebilirsiniz. Windows kullanıcıları **Ayarlar** sekmesinden yönetici izni gerektirmeden (yalnızca kendi oturumu için) Explorer sağ tık **Encrypt with RPM Encrypter** menüsünü ve `.vault` çift tık açma ilişkisini ekleyip kaldırabilir.

## Dosyaları şifreleme

Şifreleme ve çözme sırasında ilerleme çubuğunun yanında aktarım hızını (ör. MiB/s) ve tahmini kalan süreyi görebilirsiniz.

1. Dosyaları veya klasörleri uygulama penceresine sürükleyin. **Şifrele** sekmesinde listeyi ve kasanın kaydedileceği yeri kontrol edin.
2. Uzun, benzersiz bir parola girip tekrarlayın. Ek koruma için boş olmayan bir **anahtar dosyası (keyfile)** seçebilirsiniz. Bu durumda kasayı parolayla her açtığınızda aynı içeriğe sahip dosya da gerekir. Anahtar dosyasının yedeğini kasa dışında, güvenli bir yerde saklayın.
3. **Şimdi Şifrele** düğmesine basın. Ekrandaki **24 kelimelik BIP-39 kurtarma cümlesini** sırasıyla kâğıda yazın. Kaydettiğinizi onaylayıp devam edin. Bu kelimeleri bilen biri kasayı tek başına açabilir. Kâğıdı kasadan ayrı ve güvenli bir yerde tutun.
4. İşlem tamamlandığında yeni kasayı ayrı bir klasöre çözerek dosyalarınızı açabildiğinizi kontrol edin. Bu kontrolü yapana kadar asılları saklayın.

## Konteyner Boyutu (Padding) ve Gizli Kasa (Makul İnkâr Edilebilirlik)

Gerçek içerik boyutunu gizlemek veya tek bir `.vault` dosyası içine ikinci, kriptografik olarak ayırt edilemeyen bir gizli bölme yerleştirmek için sabit boyutlu konteyner kullanabilirsiniz:

- **Konteyner Boyutu (Padding):** **Şifrele** sekmesinde `Otomatik (İçerik Boyutu)` yerine `10 MiB`, `50 MiB`, `100 MiB`, `500 MiB` veya `Özel (MiB)` (1–65536 MiB arası) bir hedef boyut seçin; ya da CLI’da `--container-mb <MiB>` bayrağını verin. İçerikten kalan boşluk `OsRng` rastgele baytlarıyla doldurulur.
- **Gizli Kasa (Makul İnkâr Edilebilirlik):** **Şifrele → Gizli Kasa (Makul İnkâr Edilebilirlik)** panelini açıp onay kutusunu işaretleyin. Gizli kaynakları, dış paroladan **farklı** bir gizli parolayı ve isterseniz ayrı bir gizli anahtar dosyasını seçin. Dış parola yalnızca sahte (decoy) kasayı, gizli parola yalnızca gizli kasayı açar; dışarıdan bakıldığında dosyanın normal dolgulu bir kasadan ayırt edilmesi mümkün değildir.
- **Stealth Modu (Şifreli Başlık):** **Şifrele** sekmesinde **Stealth Modu (Şifreli Başlık)** kutucuğunu işaretleyerek (veya CLI’da `--stealth` vererek) baştaki düz metin `RPMV` imzasını ve JSON başlığı kaldırabilirsiniz. Dosya ilk bayttan son bayta kadar rastgele gürültü gibi görünür, herhangi bir uzantıyla (`.bin`, `.dat` vb.) yeniden adlandırılabilir; her zaman sabit OWASP Argon2id profilini (`64 MiB / 3 yineleme / 4 paralellik`) kullanır ve parolasız kontrolde yalnızca dosya boyutu ile SHA-256 özetini gösterir. Sabit boyut, Gizli Kasa ve dış kasa için 24 kelimelik kurtarma cümlesi ile birlikte kullanılabilir.
- **Reed-Solomon Bit-Rot Koruması (~%7 parite):** **Şifrele** sekmesinde **Reed-Solomon Bit-Rot Koruması (~%7 parite)** kutucuğunu işaretleyerek (veya CLI’da `--reed-solomon` vererek) standart, dolgulu veya gizli v5 kasalarını disk bozulmasına karşı koruyabilirsiniz (`16.320` baytlık her blokta `512` ardışık bozuk bayta kadar otomatik düzeltme). Stealth Modu ile birlikte seçilemez (şifresiz parite sendromları dosyayı rastgele gürültüden ayırt edilebilir kılar) ve RS korumalı kasalarda `rekey` kapalıdır.
- **Önemli kısıtlar:**
  - Gizli kasa için sabit bir konteyner boyutu zorunludur (`Otomatik` kullanılamaz).
  - **24 kelimelik kurtarma cümlesi yalnızca dış (sahte) kasayı açar;** makul inkâr edilebilirlik gereği gizli kasa için kurtarma cümlesi oluşturulmaz.
  - Makul inkâr edilebilirliği korumak amacıyla sabit boyutlu (dolgulu) konteynerlerde **Anahtar Değiştir (`rekey`)** devre dışıdır.
  - **Çöz**, **İncele** ve **Kasa Karşılaştırma (Vault Diff)** girilen kimlik bilgisine göre dış veya gizli bölmeyi otomatik seçer.

```sh
# Sabit 50 MiB konteyner içine dış (sahte) + gizli kasa oluşturma
./rpm-encrypter-cli encrypt ./SahteBelgeler --container-mb 50 --hidden ./GizliDosyalar --hidden-keyfile ./gizli.key

# Etkileşimsiz betiklerde: ilk satır dış parola, ikinci satır gizli parola
printf "DisParola!\nGizliParola!\n" | ./rpm-encrypter-cli encrypt ./SahteBelgeler --container-mb 10 --hidden ./GizliDosyalar --password-stdin
```

Gizli bölmeyi çözmek veya incelemek için `decrypt`, `inspect` veya `diff` komutlarında gizli parolayı (ve bağlıysa `--keyfile ./gizli.key` seçeneğini) vermeniz yeterlidir.

## Kasayı açma

`.vault` dosyasını pencereye sürükleyin. **Çöz** sekmesinde parolayı girin ve kasaya bağladıysanız anahtar dosyasını seçin (gizli bölme açıyorsanız gizli parolayı ve varsa gizli anahtar dosyasını girin). Dış kasanın parolasını veya anahtar dosyasını kaybettiyseniz kurtarma cümlesi seçeneğini işaretleyip 24 kelimeyi aynı sırayla girin. Hedef klasörü seçip **Şimdi Çöz** düğmesine basın. Çıkarılan dosyalar bu klasörde şifresiz olarak bulunur.

## Kasayı inceleme ve seçici dosya çıkarma

Tüm kasayı açmadan içeriği kontrol etmek veya yalnızca belirli dosyaları çıkarmak için **İncele** sekmesini kullanın:

- **Bütünlük Kontrolü (Parolasız) ve Onarım:** **Bütünlük Kontrolü (Parolasız)** düğmesi kasa başlığını, tüm veri parçalarının (chunk) çerçeve yapısını, sonda bozuk/artık bayt bulunmadığını (veya konteyner boyutunu), Reed-Solomon ile onarılabilir bayt sayısını ve dosyanın SHA-256 özetini parola girmeden doğrular. Disk hasarı almış Reed-Solomon korumalı kasalarda parolasız atomik onarım için **Onar (Reed-Solomon)** düğmesini (veya CLI’da `rpm-encrypter-cli repair <kasa> [-o <kopya>]` komutunu) kullanabilirsiniz.
- **Meta Veriyi İncele, RAM-İçi Önizleme ve Seçilenleri Çıkar:** Parola veya kurtarma cümlesiyle şifreli dosya listesini açtıktan sonra herhangi bir dosyanın yanındaki **Önizle** düğmesiyle (`16 MiB` sınırına kadar) UTF-8 metin veya görselleri (`PNG/JPEG/WebP/GIF/BMP`) diske tek bayt geçici dosya yazmadan yalnızca RAM içinde görüntüleyebilirsiniz (önizleme yalnızca tüm bölme AEAD doğrulamasından geçtikten sonra açılır; pencere kapatma, `Esc`, sekme veya kasa değişiminde bellek sıfırlanır). Dilerseniz onay kutularıyla seçip **Seçilenleri Çıkar** düğmesine basın. *(Arka planda seçilen bölmenin tüm şifreli parçaları yine doğrulanır.)*

## İki kasayı karşılaştırma

**İncele → Kasa Karşılaştırma (Vault Diff)** bölümünde önceki kasayı **Kasa A**, sonraki kasayı **Kasa B** olarak seçin. Her biri için parolayı ve varsa bağlı anahtar dosyasını girin veya kurtarma cümlesini kullanın. **Kasaları Karşılaştır** düğmesi yalnızca başlıklardaki dosya listelerini okur; aynı konteynerin dış ve gizli bölmeleri de farklı kimlik bilgileriyle karşılaştırılabilir. Eklenen ve silinen yollar A’dan B’ye göre gösterilir. “Değişmedi” sonucu yol, boyut ve değişiklik zamanının eşleştiği anlamına gelir. Dosya içeriklerinin birebir aynı olduğunu kanıtlamaz.

Terminalde aynı karşılaştırmayı yapmak için aşağıdaki komutu kullanın. JSON çıktı için `--json`, anahtar dosyaları için `--keyfile-a` veya `--keyfile-b`, kurtarma cümlesiyle açacağınız taraf için `--recovery-a` veya `--recovery-b` ekleyebilirsiniz.

```sh
./rpm-encrypter-cli diff ./onceki.vault ./sonraki.vault
```

## Ayarlar ve Parola Üretici

**Ayarlar** sekmesinde Argon2id yineleme sayısı (1–10), paroladan anahtar türetirken yapılan iş miktarını belirler. Paralellik (1–16), bu işin kaç şeride bölüneceğini ayarlar. Arayüzü büyütmek veya küçültmek için %80–150 arasındaki hazır ölçeklerden birini seçin. Tercihlerin sonraki açılışta da kullanılması için **Tercihleri Kaydet** düğmesine basın.

**Parola Üretici** sekmesinde büyük harf, küçük harf, rakam ve sembol sınıflarından en az birini seçin. Parolayı elle yazacaksanız karıştırılabilir karakterleri hariç tutarak `0`, `O`, `1`, `l` ve `I` karakterlerini elemeniz mümkün.

## Parolayı değiştirme

**Anahtar Değiştir** sekmesinde kasayı seçin. Mevcut parolayı, varsa bağlı anahtar dosyasını ve yeni parolayı girin. Yeni parolayı doğrulayıp **Anahtarı Güncelle** düğmesine basın.

Bu işlem yalnızca standart (dolgusuz) kasalarda kasa anahtarını yeni parolayla yeniden şifreler. Bu adımın maliyeti kasa boyutundan bağımsızdır (O(1)). Uygulama değişikliği kaydederken şifreli içeriği kopyalar. Büyük kasalarda işlem süresi uzayabilir ve diskte yaklaşık bir kasa boyutu kadar boş yer gerekir. *(Sabit boyutlu veya gizli kasa içeren konteynerler güvenlik gerekçesiyle `rekey` işlemini reddeder.)*

## Komut satırından hızlı kullanım

Örnekte paket klasöründe bir terminal açıldığı, `Belgeler` klasörünün ve `anahtar.key` dosyasının burada bulunduğu varsayılır. Windows PowerShell’de komutların başındaki `./rpm-encrypter-cli` yerine `.\rpm-encrypter-cli.exe` yazın. Parolayı program sorduğunda girin. İlk komutun sonunda gösterilen kurtarma cümlesini güvenli bir yere kaydedin.

```sh
# Klasörü parola ve anahtar dosyasıyla şifrele
./rpm-encrypter-cli encrypt ./Belgeler --keyfile ./anahtar.key

# Sabit 25 MiB konteyner olarak şifrele
./rpm-encrypter-cli encrypt ./Belgeler --container-mb 25

# Şifreli başlıkla (Stealth Modu) sabit 25 MiB konteyner oluştur
./rpm-encrypter-cli encrypt ./Belgeler --stealth --container-mb 25

# Reed-Solomon bit-rot koruması (~%7 parite) ile şifrele
./rpm-encrypter-cli encrypt ./Belgeler --reed-solomon

# Hasarlı Reed-Solomon kasasını parolasız atomik olarak onar (yerinde veya kopyaya)
./rpm-encrypter-cli repair ./Belgeler.vault
./rpm-encrypter-cli repair ./Belgeler.vault -o ./Belgeler.onarildi.vault

# Dış + gizli bölme oluştur (sıkıştırmasız gizli bölme + gizli keyfile)
./rpm-encrypter-cli encrypt ./Sahte --container-mb 50 --hidden ./Gizli --hidden-keyfile ./gizli.key --hidden-no-compress

# Oluşan kasayı aç (çıktıda farklı bir kasa adı gördüyseniz onu kullanın)
./rpm-encrypter-cli decrypt ./Belgeler.vault --keyfile ./anahtar.key

# Kurtarma cümlesiyle aç (yalnızca dış bölme için geçerlidir)
./rpm-encrypter-cli decrypt ./Belgeler.vault --recovery

# Yalnızca tek dosya veya alt klasör seçerek aç (--only tekrarlanabilir)
./rpm-encrypter-cli decrypt ./Belgeler.vault --only Belgeler/notlar.txt

# Parola istemeden yapısal bütünlük + SHA-256 kontrolü
./rpm-encrypter-cli inspect ./Belgeler.vault --integrity-only

# Aynı anahtar dosyasını kullanarak parolayı değiştir (dolgusuz kasalarda)
./rpm-encrypter-cli rekey ./Belgeler.vault --keyfile ./anahtar.key
```

`encrypt` ve `decrypt` komutlarında `--progress` seçeneği, hız ve tahmini kalan süre bilgilerinin standart hata akışına (`stderr`) ne zaman yazılacağını belirler. `auto` varsayılandır ve yalnızca etkileşimli terminalde gösterir. `always` çıktı yönlendirilse de gösterir. `never` ilerleme bilgisini kapatır.

```sh
./rpm-encrypter-cli decrypt ./Belgeler.vault --keyfile ./anahtar.key --progress always
```

## Windows için WinGet manifesti oluşturma

Windows ZIP paketini ve `SHA256SUMS.txt` dosyasını `dist/` klasörüne koyun. Proje kökünde PowerShell ile aşağıdaki komutları çalıştırın. Betik, manifestleri `dist/winget/RPM147.RPMEncrypter/4.4.0/` klasörüne yazar.

```powershell
.\packaging\winget\generate-manifests.ps1 -Version 4.4.0
winget validate --manifest .\dist\winget\RPM147.RPMEncrypter\4.4.0
```

WinGet’e gönderim adımları için paketleme belgesine bakın. [WinGet paketleme belgesi](../packaging/winget/README.md)

## SSD ve güvenli silme

SSD ve USB belleklerde **güvenli silme** seçeneği eski verilerin fiziksel olarak silinmesini garanti edemez. Yedekler ve eşitlenen klasörler de şifresiz kopyalar içerebilir. Hassas dosyalarla çalışıyorsanız en baştan tam disk şifrelemesi kullanın. [Güvenlik ayrıntıları](../SECURITY.md)
