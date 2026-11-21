# RPM Encrypter kullanım kılavuzu

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

## Kasayı açma

`.vault` dosyasını pencereye sürükleyin. **Çöz** sekmesinde parolayı girin ve kasaya bağladıysanız anahtar dosyasını seçin. Parolanızı veya anahtar dosyanızı kaybettiyseniz kurtarma cümlesi seçeneğini işaretleyip 24 kelimeyi aynı sırayla girin. Hedef klasörü seçip **Şimdi Çöz** düğmesine basın. Çıkarılan dosyalar bu klasörde şifresiz olarak bulunur.

## Kasayı inceleme ve seçici dosya çıkarma

Tüm kasayı açmadan içeriği kontrol etmek veya yalnızca belirli dosyaları çıkarmak için **İncele** sekmesini kullanın:

- **Bütünlük Kontrolü (Parolasız):** Kasa başlığını, tüm veri parçalarının (chunk) çerçeve yapısını, sonda bozuk/artık bayt bulunmadığını ve dosyanın SHA-256 özetini parola girmeden doğrular.
- **Meta Veriyi İncele ve Seçilenleri Çıkar:** Parola veya kurtarma cümlesiyle şifreli dosya listesini açtıktan sonra arama kutusu ve onay kutularıyla yalnızca istediğiniz dosya/klasörleri seçip **Seçilenleri Çıkar** düğmesine basın. *(Arka planda kasanın tüm şifreli parçaları yine doğrulanır; yalnızca seçtiğiniz öğeler diske yazılır.)*

## Parolayı değiştirme

**Anahtar Değiştir** sekmesinde kasayı seçin. Mevcut parolayı, varsa bağlı anahtar dosyasını ve yeni parolayı girin. Yeni parolayı doğrulayıp **Anahtarı Güncelle** düğmesine basın.

Bu işlem yalnızca kasa anahtarını yeni parolayla yeniden şifreler. Bu adımın maliyeti kasa boyutundan bağımsızdır (O(1)). Uygulama değişikliği kaydederken şifreli içeriği kopyalar. Büyük kasalarda işlem süresi uzayabilir ve diskte yaklaşık bir kasa boyutu kadar boş yer gerekir.

## Komut satırından hızlı kullanım

Örnekte paket klasöründe bir terminal açıldığı, `Belgeler` klasörünün ve `anahtar.key` dosyasının burada bulunduğu varsayılır. Windows PowerShell’de komutların başındaki `./rpm-encrypter-cli` yerine `.\rpm-encrypter-cli.exe` yazın. Parolayı program sorduğunda girin. İlk komutun sonunda gösterilen kurtarma cümlesini güvenli bir yere kaydedin.

```sh
# Klasörü parola ve anahtar dosyasıyla şifrele
./rpm-encrypter-cli encrypt ./Belgeler --keyfile ./anahtar.key

# Oluşan kasayı aç (çıktıda farklı bir kasa adı gördüyseniz onu kullanın)
./rpm-encrypter-cli decrypt ./Belgeler.vault --keyfile ./anahtar.key

# Kurtarma cümlesiyle aç
./rpm-encrypter-cli decrypt ./Belgeler.vault --recovery

# Yalnızca tek dosya veya alt klasör seçerek aç (--only tekrarlanabilir)
./rpm-encrypter-cli decrypt ./Belgeler.vault --only Belgeler/notlar.txt

# Parola istemeden yapısal bütünlük + SHA-256 kontrolü
./rpm-encrypter-cli inspect ./Belgeler.vault --integrity-only

# Aynı anahtar dosyasını kullanarak parolayı değiştir
./rpm-encrypter-cli rekey ./Belgeler.vault --keyfile ./anahtar.key
```

`encrypt` ve `decrypt` komutlarında `--progress` seçeneği, hız ve tahmini kalan süre bilgilerinin standart hata akışına (`stderr`) ne zaman yazılacağını belirler. `auto` varsayılandır ve yalnızca etkileşimli terminalde gösterir. `always` çıktı yönlendirilse de gösterir. `never` ilerleme bilgisini kapatır.

```sh
./rpm-encrypter-cli decrypt ./Belgeler.vault --keyfile ./anahtar.key --progress always
```

## Windows için WinGet manifesti oluşturma

Windows ZIP paketini ve `SHA256SUMS.txt` dosyasını `dist/` klasörüne koyun. Proje kökünde PowerShell ile aşağıdaki komutları çalıştırın. Betik, manifestleri `dist/winget/RPM147.RPMEncrypter/4.0.1/` klasörüne yazar.

```powershell
.\packaging\winget\generate-manifests.ps1 -Version 4.0.1
winget validate --manifest .\dist\winget\RPM147.RPMEncrypter\4.0.1
```

WinGet’e gönderim adımları için paketleme belgesine bakın. [WinGet paketleme belgesi](../packaging/winget/README.md)

## SSD ve güvenli silme

SSD ve USB belleklerde **güvenli silme** seçeneği eski verilerin fiziksel olarak silinmesini garanti edemez. Yedekler ve eşitlenen klasörler de şifresiz kopyalar içerebilir. Hassas dosyalarla çalışıyorsanız en baştan tam disk şifrelemesi kullanın. [Güvenlik ayrıntıları](../SECURITY.md)
