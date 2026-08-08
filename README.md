# 🛡 Silva v4.1 — Akıllı Ağ Güvenliği ve Risk Analiz Aracı (Tamamen Ücretsiz)

> **v4.1 notu:** Gerçek bir kullanıcı taramasında (225 bağlantı) yaşanan yüksek yanlış-pozitif oranı
> düzeltildi: beacon tespiti artık gerçek yeniden-bağlanma kanıtı arıyor (tek açık bağlantıyı değil),
> komut satırı deseni tespiti daraltıldı (Electron/Chromium alt-süreçleri artık gürültü üretmiyor),
> script kendi başlatma komutunu artık analiz etmiyor, ve imzalı-ama-AppData'dan-çalışan yaygın
> uygulamalar (Telegram, Discord, Spotify vb.) artık otomatik Düşük/Orta seviyeye düşüyor. Detaylar
> için aşağıdaki "Risk Sınıflandırma Mantığı" bölümüne bakın.

**Silva**, Windows sistemlerde aktif ağ bağlantılarını, bu bağlantılara sahip süreçleri, servisleri ve
sistem kalıcılık (persistence) noktalarını tarayarak potansiyel güvenlik risklerini tespit eden,
PowerShell tabanlı, **%100 ücretsiz ve açık kaynak** bir uç nokta (endpoint) güvenlik analiz aracıdır.

Kurumsal EDR (Endpoint Detection & Response) çözümlerinin temel mantığından ilham alır:
**bağlantı → süreç → ebeveyn süreç → komut satırı → dosya → imza → coğrafi konum** zincirini kurar,
her satırı bir risk skoruna dönüştürür ve hem teknik hem teknik olmayan kullanıcıların anlayabileceği bir rapor üretir.

> 💸 **Hiçbir ücret, lisans anahtarı veya kayıt gerektirmez.** Kullandığı tüm dış servisler (GeoIP sorgusu, Discord bildirimi) ücretsiz katmanlardır.

---

## 🆕 v4.0 ile Gelenler

| Yenilik | Ne İşe Yarar |
|---|---|
| 🧬 **Ebeveyn Süreç + Komut Satırı Analizi** | `winword.exe -> powershell.exe` gibi klasik makro-zararlı zincirlerini ve `-enc`, gizli pencere, indirme komutları gibi şüpheli komut satırı desenlerini yakalar |
| 🎯 **Yol + Yayıncı Eşleştirmeli Güven Kontrolü** | "chrome.exe" adında ama Chrome'un kurulu olduğu klasörde olmayan bir dosyayı, ismi geçse bile şüpheli sayar |
| 📡 **Derin Tarama Modu (Beacon Tespiti)** | Aynı dış IP'ye kısa aralıklarla tekrar bağlanan süreçleri işaretleyerek düzenli C2 "check-in" davranışına işaret eder |
| ⚙ **Servis + Başlangıç Klasörü Taraması** | Run/RunOnce kayıtlarına ek olarak otomatik başlayan imzasız servisleri ve Başlangıç klasöründeki dosyaları da tarar |
| 📄 **JSON Dışa Aktarım** | SIEM'e aktarım veya otomasyon için makine-okunabilir rapor |
| 🔕 **Sessiz Mod (`-Silent`)** | Hiç soru sormadan tarar, rapor üretir — zamanlanmış görevler için ideal |
| 🔔 **Discord Webhook Bildirimi** | Kritik/yüksek bulgu veya yeni IP tespit edildiğinde ücretsiz Discord webhook'una otomatik uyarı gönderir |
| ⏰ **Tek Komutla Otomatik Günlük Tarama** | `-InstallScheduledTask` ile her gün arka planda sessizce taranmasını sağlar |
| 🧙 **İlk Kurulum Sihirbazı** | İlk çalıştırmada 2 basit soruyla (Discord bildirimi ister misin? Otomatik taransın mı?) kurulumu tamamlar |
| 🧾 **Çalışma Günlüğü (Log)** | Her taramanın ne zaman, hangi sonuçla çalıştığı `%LOCALAPPDATA%\Silva\logs` altında saklanır |
| 🚦 **Çıkış Kodları** | `0` temiz, `1` yüksek risk, `2` kritik risk — otomasyon/SIEM entegrasyonu için |

---

## 📌 Ne İşe Yarar?

Modern zararlı yazılımların büyük çoğunluğu, sisteme sızdıktan sonra bir şekilde **dışarıyla iletişim kurar**
(komut-kontrol sunucusu, veri sızdırma, ek modül indirme vb.). Silva bu iletişimi yakalamak için sistemin
ağ katmanını anlık (on-demand) veya günlük otomatik olarak derinlemesine tarar ve şu soruları otomatik yanıtlar:

- Bu bağlantıyı hangi süreç açtı, o süreç nerede duruyor, hangi süreç tarafından başlatıldı?
- Süreç dijital olarak imzalanmış mı, imza güvenilir bir yayıncıya mı ait?
- Süreç, sistem/uygulama dosyası gibi görünüp aslında beklenmedik bir dizinden mi çalışıyor?
- Komut satırında şüpheli bir desen (base64, gizli pencere, uzaktan indirme) var mı?
- Aynı dış IP'ye anormal sıklıkta tekrar bağlanan bir "beacon" davranışı var mı?
- Bağlandığı IP hangi ülkede, hangi servis sağlayıcıya ait, daha önce görülmüş mü?
- Sistem açılışında otomatik çalışacak şekilde kayıtlı şüpheli bir program, servis veya görev var mı?

> ⚠️ Silva bir antivirüs veya EDR **yerine geçmez**. Tespit ettiği bulgular birer **gösterge (indicator)**'dir,
> kesin yargı değildir. Kritik bulgularda profesyonel bir güvenlik uzmanına danışmanız önerilir.

---

## 🚀 Hızlı Başlangıç (En Kolay Yol)

Yönetici olmayan bir PowerShell penceresinde tek satır yeterli — script gerekli yönetici yetkisini kendisi ister:

```powershell
irm https://raw.githubusercontent.com/mert478/tara/main/silva.ps1 | iex
```

Script açıldığında basit bir menü ile karşılaşırsınız:

```
Tarama modunu seçin:
  [1] Hızlı Tarama       (varsayılan, ~10-20 sn)
  [2] Derin Tarama       (+beacon/C2 davranış tespiti, ~30-40 sn)
  [3] Sessiz Mod         (soru sormaz, sadece rapor üretir)
Seçiminiz [1]:
```

Enter'a basmanız yeterli — geri kalan her şeyi Silva halleder ve masaüstünüze raporları bırakır.

İlk çalıştırmada ayrıca 2 kısa soru sorulur (istersen Enter'a basıp geçebilirsin):
- Kritik bulgularda Discord'a bildirim almak ister misin?
- Her gün otomatik (arka planda, sessiz) taransın mı?

---

## 🖥 Dosyayı İndirip Parametrelerle Çalıştırma (İleri Seviye)

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/mert478/tara/main/silva.ps1" -OutFile "silva.ps1"

# Örnekler:
powershell.exe -ExecutionPolicy Bypass -File .\silva.ps1                          # normal, menülü
powershell.exe -ExecutionPolicy Bypass -File .\silva.ps1 -Silent                  # sessiz, tek seferlik
powershell.exe -ExecutionPolicy Bypass -File .\silva.ps1 -DeepScan                # beacon tespitli derin tarama
powershell.exe -ExecutionPolicy Bypass -File .\silva.ps1 -ExportFormat JSON       # sadece JSON çıktı
powershell.exe -ExecutionPolicy Bypass -File .\silva.ps1 -DiscordWebhook "https://discord.com/api/webhooks/..."
powershell.exe -ExecutionPolicy Bypass -File .\silva.ps1 -InstallScheduledTask    # günlük otomatik tarama kur
powershell.exe -ExecutionPolicy Bypass -File .\silva.ps1 -UninstallScheduledTask  # otomatik taramayı kaldır
```

| Parametre | Açıklama |
|---|---|
| `-Silent` | Hiç soru sormaz; PID sonlandırma ve Out-GridView adımlarını atlar. Otomasyon için idealdir. |
| `-DeepScan` | ~6 saniyelik ek örnekleme ile beacon (düzenli C2 check-in) davranışı arar. |
| `-ExportFormat` | `CSV`, `HTML`, `JSON` veya `All` (varsayılan). |
| `-ConfigPath` | Alternatif bir `config.json` konumu belirtir. |
| `-DiscordWebhook` | Verilen webhook URL'sini config'e kalıcı olarak kaydeder. |
| `-InstallScheduledTask` | Her gün 09:00'da `-Silent` modda otomatik çalışacak bir görev kurar. |
| `-UninstallScheduledTask` | Kurulu otomatik görevi kaldırır. |
| `-SkipWizard` | İlk çalıştırma sihirbazını atlar. |

---

## 📋 Gereksinimler

- **İşletim Sistemi:** Windows 10 / Windows 11 / Windows Server 2016+
- **PowerShell:** 5.1 veya üzeri (Windows'ta varsayılan yüklü)
- **Yetki:** Yönetici — script otomatik olarak yükseltme talep eder
- **İnternet:** GeoIP ve Discord bildirimi için gereklidir (ikisi de tamamen opsiyonel, kapatılabilir)
- **Maliyet:** **0 ₺.** Hiçbir bileşen ücretli değildir.

---

## ⚙️ Yapılandırma

İlk çalıştırmada `%LOCALAPPDATA%\Silva\config.json` konumunda otomatik oluşturulur ve elle düzenlenebilir:

```json
{
  "TrustedProcs": ["svchost", "chrome", "..."],
  "ExpectedPaths": { "chrome": "Google\\Chrome\\Application", "svchost": "C:\\Windows\\System32" },
  "TrustedPublishers": ["Microsoft Corporation", "Google LLC", "..."],
  "CriticalPorts": [4444, 5555, 6666, 31337, 12345],
  "SuspiciousParents": ["winword", "excel", "outlook", "mshta"],
  "SuspiciousChildren": ["powershell", "cmd", "wscript", "regsvr32"],
  "GeoIPEnabled": true,
  "GeoIPProvider": "ip-api",
  "GeoIPTimeoutSec": 2,
  "DiscordWebhookUrl": "",
  "LogEnabled": true
}
```

| Alan | Açıklama |
|---|---|
| `TrustedProcs` | Bilinen/güvenilir süreç isimleri. |
| `ExpectedPaths` | Her güvenilir süreç için beklenen kurulum dizini — isim taklidi (masquerading) tespitini güçlendirir. |
| `TrustedPublishers` | Şüpheli dizinden çalışsa bile risk notunda "güvenilir yayıncı" olarak belirtilecek imza sahipleri. |
| `CriticalPorts` | Klasik backdoor portları — bu portlara giden bağlantılar doğrudan **Kritik** sayılır. |
| `SuspiciousParents` / `SuspiciousChildren` | Office/Script enjeksiyon zinciri tespiti için ebeveyn-çocuk süreç eşleşmeleri. |
| `GeoIPEnabled` | `false` yapılırsa dış IP sorgulama tamamen kapanır (daha hızlı, internet gerektirmez). |
| `GeoIPProvider` | `"ip-api"` (hızlı, toplu sorgu, HTTP) veya `"ipwho"` (HTTPS, gizliliğe daha duyarlı, tekli sorgu). |
| `DiscordWebhookUrl` | Kritik/yüksek bulgu veya yeni IP'de otomatik bildirim gönderilecek webhook adresi. |

---

## 📤 Çıktılar

| Dosya | İçerik |
|---|---|
| `Silva_Ag_Guvenlik_Raporu.html` | Renk kodlu, filtrelenebilir görsel rapor |
| `Silva_Ag_Guvenlik_Raporu.csv` | Ham veri — Excel/SIEM için |
| `Silva_Ag_Guvenlik_Raporu.json` | Makine-okunabilir, otomasyon/SIEM entegrasyonu için özet + detay |
| `%LOCALAPPDATA%\Silva\history.json` | Taramalar arası IP karşılaştırma geçmişi |
| `%LOCALAPPDATA%\Silva\logs\*.log` | Her çalıştırmanın kaydı |

---

## 🧩 Risk Sınıflandırma Mantığı (v4)

| Seviye | Tetiklenme Koşulu |
|---|---|
| 🔴 **Kritik** | Bilinen kötü amaçlı port · Sistem/uygulama sürecini taklit eden dosya (isim+yol uyuşmazlığı) · Office/Script enjeksiyon zinciri · Dış bağlantı + gerçekten şüpheli komut satırı (base64 blob, gizli pencere, indirme zinciri vb.) · İmzasız + Temp/AppData'dan çalışan süreç |
| 🟠 **Yüksek** | Şüpheli komut satırı deseni (iç bağlantıda) · İmzasız süreç dış ağa bağlanıyor · Gerçek yeniden-bağlanma kanıtlı olası beacon davranışı (Derin Tarama, farklı yerel port ile aynı IP'ye tekrar bağlanma) |
| 🟡 **Orta** | Sahipsiz/kapanmış sürece ait bağlantı · Whitelist dışı program dış ağla konuşuyor · İmzalı ama tanınmayan yayıncıya ait, Temp/AppData altından çalışan süreç (ör. az bilinen bir uygulama) |
| 🟢 **Düşük** | Bilinen/güvenilir süreç, normal davranış · İmzalı ve güvenilir yayıncıya ait, AppData altından çalışan yaygın uygulamalar (Discord, Spotify, Telegram vb. — bu, tasarım gereğidir, güvenlik açığı değildir) |

**Beacon tespiti nasıl çalışır (v4.1):** Eskiden "aynı bağlantı 3 kez görüldü" beacon sayılıyordu — bu
yanlıştı, çünkü herhangi bir uzun ömürlü normal bağlantı (Discord sesli sohbet, Spotify akışı, tarayıcı
sekmesi) da birkaç saniyede birkaç kez "açık" görünür. Artık algoritma, aynı süreç + aynı uzak IP için
**farklı yerel portlarla tekrar bağlantı kurulduğunu** (yani bağlantının kapanıp yeniden açıldığını) arıyor
— bu, gerçek bir periyodik "check-in" döngüsünün daha güvenilir bir göstergesidir.

---

## 🔒 Gizlilik Notu

Silva, dış IP adreslerinin coğrafi konum/ISP bilgisini almak için varsayılan olarak
[ip-api.com](https://ip-api.com) (ücretsiz, HTTP) servisini kullanır. Daha gizlilik odaklı bir seçenek
istersen `config.json` içinde `"GeoIPProvider": "ipwho"` yaparak HTTPS üzerinden [ipwho.is](https://ipwho.is)
servisine geçebilir, ya da `"GeoIPEnabled": false` ile tamamen kapatabilirsin. Discord webhook'u yalnızca
sen ayarlarsan ve yalnızca kendi sunucuna bildirim gönderir — üçüncü bir tarafla veri paylaşılmaz.

---

## 🗺 Yol Haritası

- [x] Ebeveyn süreç + komut satırı analizi
- [x] Yol + yayıncı eşleştirmeli güven kontrolü
- [x] JSON/SIEM uyumlu çıktı
- [x] Discord Webhook bildirimi
- [x] Zamanlanmış görev olarak otomatik tarama
- [x] Basit beacon (C2 check-in) tespiti
- [ ] AbuseIPDB / VirusTotal entegrasyonu ile bilinen kötü amaçlı IP kontrolü
- [ ] WMI Event Subscription tabanlı fileless persistence tespiti
- [ ] Pester ile otomatik test paketi

---

## 🤝 Katkıda Bulunma

Pull request'ler ve issue'lar memnuniyetle karşılanır. Büyük değişiklik önerileri için önce bir issue açarak
tartışmaya açmanız önerilir.

## ⚖️ Sorumluluk Reddi

Bu araç **eğitim ve ön analiz amaçlıdır**. Üretilen bulgular kesin bir güvenlik ihlali kanıtı değildir ve
profesyonel bir güvenlik değerlendirmesinin yerini tutmaz. Aracın kullanımından doğabilecek herhangi bir veri
kaybı veya sistem sorunundan geliştirici sorumlu tutulamaz.

## 📄 Lisans

Bu proje [MIT Lisansı](LICENSE) ile lisanslanmıştır. **Tamamen ücretsiz ve açık kaynaktır, ücretli bir sürümü yoktur.**
