# 🛡 Silva — Akıllı Ağ Güvenliği ve Risk Analiz Aracı

**Silva**, Windows sistemlerde aktif ağ bağlantılarını, bu bağlantılara sahip süreçleri ve sistem kalıcılık (persistence) noktalarını tarayarak potansiyel güvenlik risklerini tespit eden, PowerShell tabanlı bir uç nokta (endpoint) güvenlik analiz aracıdır.

Kurumsal EDR (Endpoint Detection & Response) çözümlerinin temel mantığından ilham alır: **bağlantı → süreç → dosya → imza → coğrafi konum** zincirini kurup her satırı bir risk skoruna dönüştürür ve okunabilir bir rapor üretir.

---

## 📌 Ne İşe Yarar?

Modern zararlı yazılımların büyük çoğunluğu, sisteme sızdıktan sonra bir şekilde **dışarıyla iletişim kurar** (komut-kontrol sunucusu, veri sızdırma, ek modül indirme vb.). Silva bu iletişimi yakalamak için sistemin ağ katmanını sürekli değil, anlık (on-demand) olarak derinlemesine tarar ve şu soruları otomatik olarak yanıtlar:

- Bu bağlantıyı hangi süreç açtı, o süreç nerede duruyor?
- Bu süreç dijital olarak imzalanmış mı, imzayı kim vermiş?
- Süreç, sistem dosyası gibi görünüp aslında `AppData`/`Temp` gibi şüpheli bir dizinden mi çalışıyor?
- Bağlandığı IP hangi ülkede, hangi servis sağlayıcıya (ISP) ait?
- Bu IP daha önce görülmüş müydü, yoksa bu taramada ilk kez mi ortaya çıktı?
- Sistem açılışında otomatik çalışacak şekilde kayıtlı (persistence) şüpheli bir program var mı?

Elde edilen bulgular risk seviyesine göre sınıflandırılır ve hem teknik olmayan kullanıcıların anlayabileceği hem de ileri analiz için CSV'ye aktarılabilecek bir rapor haline getirilir.

### Tipik Kullanım Senaryoları

- Şüpheli bir davranış fark eden kullanıcıların sistemlerini hızlıca ön analizden geçirmesi
- BT/güvenlik ekiplerinin uç noktalarda hızlı triage (ilk değerlendirme) yapması
- Sistem yöneticilerinin periyodik ağ hijyeni kontrolleri
- Güvenlik eğitimlerinde canlı bir analiz aracı örneği olarak kullanılması

> ⚠️ Silva bir antivirüs veya EDR **yerine geçmez**. Tespit ettiği bulgular birer **gösterge (indicator)**'dir, kesin yargı değildir. Şüpheli bulgularda profesyonel bir güvenlik uzmanına danışmanız önerilir.

---

## ✨ Özellikler

| Özellik | Açıklama |
|---|---|
| 🔍 **Bağlantı Taraması** | Tüm aktif TCP bağlantılarını, sahibi olan süreçle eşleştirir |
| 🔏 **Dijital İmza Doğrulaması** | Her sürecin çalıştırılabilir dosyasını Authenticode ile doğrular, imzasız/geçersiz dosyaları işaretler |
| 🌍 **GeoIP / ISP Zenginleştirme** | Dış IP'lerin ülke ve servis sağlayıcı bilgisini toplu (batch) sorgulama ile getirir |
| 🧠 **Çok Katmanlı Risk Motoru** | Port, dizin, imza durumu ve whitelist bilgisini birleştirerek Düşük/Orta/Yüksek/Kritik skoru üretir |
| 🔁 **Kalıcılık (Persistence) Taraması** | Run/RunOnce registry anahtarlarını ve Microsoft dışı zamanlanmış görevleri listeler |
| 🕓 **Geçmişle Karşılaştırma** | Önceki taramalarda görülmeyen yeni dış IP'leri otomatik olarak vurgular |
| ⚙️ **Yapılandırılabilir** | Güvenilir süreç listesi ve kritik port listesi harici bir `config.json` üzerinden özelleştirilebilir |
| 📊 **Çift Format Rapor** | Hem görsel HTML raporu hem de içe aktarılabilir CSV çıktısı üretir |
| 🧹 **İnteraktif Müdahale** | Riskli bulunan süreçleri rapor üzerinden doğrudan (çoklu PID desteğiyle) sonlandırma imkânı |
| 🖥 **Grid Görünümü** | `Out-GridView` ile sonuçları filtrelenebilir, sıralanabilir tablo halinde sunar |

---

## 🚀 Çalıştırma Seçenekleri

### Seçenek 1 — Tek Satırla Uzaktan Çalıştırma (Önerilen)

Yönetici olmayan bir PowerShell penceresinde aşağıdaki komutu çalıştırmanız yeterlidir. Script gerekli yönetici yetkisini **kendisi talep eder**:

```powershell
irm https://raw.githubusercontent.com/mert478/tara/main/silva.ps1 | iex
```

> `irm` (`Invoke-RestMethod`) scripti indirir, `iex` (`Invoke-Expression`) çalıştırır. Ek bir dosya indirmenize gerek yoktur.

### Seçenek 2 — Dosyayı İndirip Çalıştırma

```powershell
# 1) Scripti indirin
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/mert478/tara/main/silva.ps1" -OutFile "silva.ps1"

# 2) Çalıştırın (yönetici penceresi otomatik açılır)
powershell.exe -ExecutionPolicy Bypass -File .\silva.ps1
```

veya `silva.ps1` dosyasına sağ tıklayıp **"PowerShell ile Çalıştır"** seçeneğini kullanabilirsiniz.

### Seçenek 3 — Repoyu Klonlayarak

```powershell
git clone https://github.com/mert478/tara.git
cd tara
powershell.exe -ExecutionPolicy Bypass -File .\silva.ps1
```

---

## 📋 Gereksinimler

- **İşletim Sistemi:** Windows 10 / Windows 11 / Windows Server 2016+
- **PowerShell:** 5.1 veya üzeri (Windows'ta varsayılan olarak yüklüdür)
- **Yetki:** Yönetici (Administrator) — script otomatik olarak yükseltme talep eder
- **İnternet Bağlantısı:** GeoIP sorguları için gereklidir (kapatılabilir, bkz. [Yapılandırma](#️-yapılandırma))
- **Execution Policy:** Kısıtlıysa script `-ExecutionPolicy Bypass` ile kendi kendini başlatır, elle ayar değiştirmenize gerek yoktur

---

## ⚙️ Yapılandırma

İlk çalıştırmada `%LOCALAPPDATA%\Silva\config.json` konumunda otomatik bir yapılandırma dosyası oluşturulur:

```json
{
  "TrustedProcs": ["svchost", "lsass", "csrss", "explorer", "chrome", "..."],
  "CriticalPorts": [4444, 5555, 6666, 31337, 12345],
  "GeoIPEnabled": true,
  "GeoIPTimeoutSec": 2
}
```

| Alan | Açıklama |
|---|---|
| `TrustedProcs` | Bilinen/güvenilir süreç isimleri listesi. Buradaki isimler dış bağlantı kurduğunda otomatik risk artışına neden olmaz. |
| `CriticalPorts` | Klasik zararlı yazılım/backdoor portları. Bu portlara giden bağlantılar doğrudan **Kritik** olarak işaretlenir. |
| `GeoIPEnabled` | `false` yapılırsa dış IP sorgulama tamamen devre dışı kalır (internet gerektirmez, daha hızlı çalışır). |
| `GeoIPTimeoutSec` | GeoIP isteklerinin zaman aşımı süresi (saniye). |

Dosyayı düzenledikten sonra bir sonraki çalıştırmada değişiklikler otomatik olarak uygulanır.

---

## 📤 Çıktılar

Her çalıştırma sonunda masaüstünüze iki dosya kaydedilir:

| Dosya | İçerik |
|---|---|
| `Silva_Ag_Guvenlik_Raporu.html` | Renk kodlu, filtrelenebilir görsel rapor — risk özetini, bağlantı tablosunu, kalıcılık kayıtlarını ve zamanlanmış görevleri içerir |
| `Silva_Ag_Guvenlik_Raporu.csv` | Ham veri — Excel'de analiz, SIEM'e aktarma veya arşivleme için |

Ayrıca `%LOCALAPPDATA%\Silva\history.json` dosyasında taramalar arası karşılaştırma için IP geçmişi tutulur.

---

## 🧩 Risk Sınıflandırma Mantığı

| Seviye | Tetiklenme Koşulu |
|---|---|
| 🔴 **Kritik** | Bilinen kötü amaçlı port kullanımı · Sistem sürecini taklit eden sahte dosya · İmzasız + Temp/AppData dizininden çalışan süreç |
| 🟠 **Yüksek** | İmzalı ama şüpheli dizinden çalışan süreç · İmzasız süreç dış ağa bağlanıyor |
| 🟡 **Orta** | Sahipsiz/kapanmış sürece ait bağlantı · Whitelist dışı bir program dış ağla konuşuyor |
| 🟢 **Düşük** | Bilinen/güvenilir süreç, normal davranış |

---

## 🛠 İnteraktif Süreç Sonlandırma

Tarama sonunda Kritik/Yüksek riskli bulgular varsa, terminal üzerinden ilgili PID'leri girerek doğrudan sonlandırabilirsiniz:

```
Sonlandırmak istediğiniz PID'leri virgülle ayırarak yazın (örn: 1234,5678) veya Enter'a basıp geçin
```

> ⚠️ Bir süreci sonlandırmadan önce raporu dikkatlice inceleyin. Meşru bir sistem sürecini yanlışlıkla kapatmak sistem kararlılığını etkileyebilir.

---

## 🔒 Gizlilik Notu

Silva, dış IP adreslerini coğrafi konum/ISP bilgisi almak amacıyla [ip-api.com](https://ip-api.com) servisine gönderir. Başka hiçbir veri (dosya içeriği, kişisel bilgi, kimlik bilgisi vb.) üçüncü bir tarafa iletilmez. GeoIP özelliği `config.json` üzerinden tamamen kapatılabilir.

---

## 🗺 Yol Haritası

- [ ] AbuseIPDB / VirusTotal entegrasyonu ile bilinen kötü amaçlı IP kontrolü
- [ ] E-posta / Discord Webhook ile kritik bulgu bildirimi
- [ ] Zamanlanmış görev olarak arka planda periyodik tarama
- [ ] JSON/HTML dışında SIEM uyumlu (CEF/Syslog) çıktı formatı

---

## 🤝 Katkıda Bulunma

Pull request'ler ve issue'lar memnuniyetle karşılanır. Büyük değişiklik önerileri için önce bir issue açarak tartışmaya açmanız önerilir.

## ⚖️ Sorumluluk Reddi

Bu araç **eğitim ve ön analiz amaçlıdır**. Üretilen bulgular kesin bir güvenlik ihlali kanıtı değildir ve profesyonel bir güvenlik değerlendirmesinin yerini tutmaz. Aracın kullanımından doğabilecek herhangi bir veri kaybı veya sistem sorunundan geliştirici sorumlu tutulamaz.

## 📄 Lisans

Bu proje [MIT Lisansı](LICENSE) ile lisanslanmıştır.
