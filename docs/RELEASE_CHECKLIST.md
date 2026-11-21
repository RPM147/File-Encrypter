# v4.0.2 sürüm kontrol listesi

## Etiketten önce

- [ ] **CI.** Etiketlenecek commit için Windows ve Ubuntu işleri ile RustSec, lisans ve bağımlılık kaynağı denetimlerini yapan `dependency-audit` işi başarılı. [CI çalışmaları](https://github.com/RPM147/File-Encrypter/actions/workflows/ci.yml)
- [ ] **ZIP ve SHA-256.** Aday commit’ten proje kökünde `.\scripts\package-release.ps1` çalıştır. `Get-FileHash .\dist\rpm-encrypter-4.0.2-windows-x86_64.zip -Algorithm SHA256` çıktısını `dist\SHA256SUMS.txt` içindeki aynı dosya adı ve özetle karşılaştır. Özetler büyük/küçük harften bağımsız eşleşmeli. ZIP’i boş bir klasöre çıkar. İki EXE ile `README.md`, `SECURITY.md`, `LICENSE` ve `docs/USER_GUIDE.md` dosyaları bulunmalı. `rpm-encrypter.exe` simgesini Explorer’da, `4.0.2` dosya/ürün sürümünü Dosya Özellikleri → Ayrıntılar’da doğrula.
- [ ] **Sürüm notu başlığı.** Etiketlenecek commit’te `CHANGELOG.md` içinde tek bir `## v4.0.2` başlığı ve altında İngilizce sürüm notları bulunuyor.
- [ ] **Türkçe yazı tipi.** ZIP’ten çıkan `rpm-encrypter.exe` dosyasını aç; varsayılan olarak Türkçe arayüzle açıldığını ve EN/TR dil geçişinin çalıştığını doğrula. Sekmelerde ve düğmelerde “Şifrele”, “Çöz” ve “İncele” okunuyor. Dosya listesinde `Iğdır-ölçü.txt` adı eksik karakter veya kare kutu olmadan görünüyor.
- [ ] **Sürükle-bırak.** İki farklı deneme dosyası içeren bir klasörü pencereye bırakıp şifrele. Oluşan `.vault` dosyasını pencereye bırak. **Çöz** sekmesi açılıyor ve boş bir hedef klasöre geri yüklenen iki dosyanın içeriği asıllarıyla eşleşiyor.
- [ ] **Seçici çıkarma.** Aynı kasayı **İncele** sekmesinde açıp meta veriyi görüntüle. İki dosyadan birini seçip **Seçilenleri Çıkar** ile başka bir boş klasöre çıkar. Seçilen dosyanın içeriği doğru ve diğer dosya hedefte yok.
- [ ] **Windows sağ tık (HKCU).** Standart kullanıcı hesabında Ayarlar’dan Explorer entegrasyonunu etkinleştir. Bir deneme dosyasının sağ tık menüsünden şifrelemeyi aç ve doğru dosyanın seçildiğini gör. Entegrasyonu kaldırıp menü öğesinin kaybolduğunu doğrula.

- [ ] **Kasa Karşılaştırma.** Bir deneme klasörünü A kasasına kaydet. Bir dosya ekle, birini sil, birinin boyutunu değiştir ve bir dosyayı olduğu gibi bırak. Aynı klasörü B kasasına kaydet. **İncele → Kasa Karşılaştırma** ekranındaki dört grubun `rpm-encrypter-cli diff A.vault B.vault --json` çıktısıyla ve yaptığın değişikliklerle eşleştiğini doğrula.
- [ ] **Ayarlar.** Argon2id için 4 yineleme ve 2 paralellik seç. Arayüzü %120 ölçeğe getirip **Tercihleri Kaydet** düğmesine bas. Uygulamayı yeniden açınca üç değer korunmalı ve yeni oluşturulan bir deneme kasası çözülebilmeli.
- [ ] **Parola Üretici.** Yalnızca rakamları etkinleştir ve karıştırılabilir karakter filtresini aç. Üretilen parolada yalnızca 2–9 rakamları bulunmalı. Ardından yalnızca sembolleri seçip üretilen parolada harf veya rakam bulunmadığını doğrula.

## Yayından sonra

- [ ] **Otomatik sürüm notları.** GitHub Release açıklamasının `CHANGELOG.md` içindeki `v4.0.2` bölümünün gövdesiyle eşleştiğini doğrula. [Release iş akışı](https://github.com/RPM147/File-Encrypter/actions/workflows/release.yml)
- [ ] **Derleme kaynağı (provenance).** Yayımlanan Windows ZIP ve Linux TAR.GZ dosyalarının her biri için `gh attestation verify <arşiv> --repo RPM147/File-Encrypter --signer-workflow RPM147/File-Encrypter/.github/workflows/release.yml --source-ref refs/tags/v4.0.2` komutunu çalıştır. Her iki doğrulama da başarılı olmalı. [GitHub CLI başvurusu](https://cli.github.com/manual/gh_attestation_verify)
