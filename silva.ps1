# =====================================================================
#   SİLVA - AKILLI AĞ GÜVENLİĞİ VE RİSK ANALİZ ARACI  v4.0  (ÜCRETSİZ)
#   Yenilikler:
#     - Ebeveyn süreç + komut satırı analizi (Office/Script enjeksiyon zinciri)
#     - Yol + Yayıncı (publisher) eşleştirmeli güven kontrolü
#     - Şüpheli komut satırı deseni tespiti (obfuscation / indirme / gizli pencere)
#     - Derin Tarama modu: basit "beacon" (düzenli C2 check-in) tespiti
#     - Servis (Win32_Service) ve Başlangıç Klasörü taraması
#     - JSON / CEV-benzeri dışa aktarım (SIEM uyumlu)
#     - Sessiz mod (-Silent) + parametre desteği -> otomasyon / zamanlanmış görev
#     - Discord Webhook ile kritik bulgu bildirimi (opsiyonel, ücretsiz)
#     - Tek komutla zamanlanmış görev kurulumu (-InstallScheduledTask)
#     - Basit ilk-kurulum sihirbazı + kolay kullanım menüsü
#     - Çalışma günlüğü (log) dosyası
# =====================================================================

[CmdletBinding()]
param(
    [switch]$Silent,                                   # Hiçbir soru sormaz, sadece tarar ve raporlar
    [switch]$DeepScan,                                  # Beacon tespiti için birkaç saniye ek örnekleme yapar
    [ValidateSet("CSV","HTML","JSON","All")]
    [string]$ExportFormat = "All",
    [string]$ConfigPath,
    [switch]$InstallScheduledTask,                      # Günlük otomatik tarama görevi kurar ve çıkar
    [switch]$UninstallScheduledTask,                    # Kurulu zamanlanmış görevi kaldırır
    [string]$DiscordWebhook,                            # Verilirse config'e kaydedilir
    [switch]$SkipWizard                                 # İlk kurulum sihirbazını atla
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['*:Encoding'] = 'utf8'
$ErrorActionPreference = 'Continue'

$SilvaRawUrl = "https://raw.githubusercontent.com/mert478/tara/main/silva.ps1"
$SilvaVersion = "4.1"

# ---------------------------------------------------------------------
# 0) YÖNETİCİ YÜKSELTME (parametreleri koruyarak)
# ---------------------------------------------------------------------
function Get-ForwardedArgString {
    $parts = @()
    if ($Silent) { $parts += "-Silent" }
    if ($DeepScan) { $parts += "-DeepScan" }
    if ($ExportFormat -ne "All") { $parts += "-ExportFormat $ExportFormat" }
    if ($ConfigPath) { $parts += "-ConfigPath `"$ConfigPath`"" }
    if ($InstallScheduledTask) { $parts += "-InstallScheduledTask" }
    if ($UninstallScheduledTask) { $parts += "-UninstallScheduledTask" }
    if ($DiscordWebhook) { $parts += "-DiscordWebhook `"$DiscordWebhook`"" }
    if ($SkipWizard) { $parts += "-SkipWizard" }
    return ($parts -join " ")
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $fwdArgs = Get-ForwardedArgString
    if ($PSCommandPath) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $fwdArgs" -Verb RunAs
    } else {
        $cmd = "irm '$SilvaRawUrl' | iex"
        if ($fwdArgs) {
            # irm|iex parametre almadığından, self-elevation sırasında parametreleri
            # ortam değişkenleri üzerinden aktarıyoruz.
            $cmd = "`$env:SILVA_ARGS='$fwdArgs'; irm '$SilvaRawUrl' | iex"
        }
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"$cmd`"" -Verb RunAs
    }
    Exit
}

# irm|iex ile yükseltilmişse env üzerinden gelen argümanları geri parametrelere uygula
if ($env:SILVA_ARGS -and -not $PSCommandPath) {
    if ($env:SILVA_ARGS -match '-Silent') { $Silent = $true }
    if ($env:SILVA_ARGS -match '-DeepScan') { $DeepScan = $true }
    Remove-Item Env:\SILVA_ARGS -ErrorAction SilentlyContinue
}

Clear-Host
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   SİLVA v$SilvaVersion - AKILLI AĞ GÜVENLİK ANALİZİ (Ücretsiz)  " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# ---------------------------------------------------------------------
# 1) ÇALIŞMA DİZİNİ, LOG VE CONFIG YÖNETİMİ
# ---------------------------------------------------------------------
$workDir     = Join-Path $env:LOCALAPPDATA "Silva"
$logDir      = Join-Path $workDir "logs"
if (-not $ConfigPath) { $ConfigPath = Join-Path $workDir "config.json" }
$historyPath = Join-Path $workDir "history.json"

foreach ($d in @($workDir, $logDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
}

$logPath = Join-Path $logDir ("silva_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    try { Add-Content -Path $logPath -Value $line -Encoding UTF8 } catch {}
}

$isFirstRun = -not (Test-Path $ConfigPath)

if ($isFirstRun) {
    $defaultConfig = @{
        TrustedProcs      = @("svchost","lsass","csrss","wininit","services","explorer","chrome",
                               "firefox","msedge","discord","spotify","steam","code","powershell","cmd",
                               "telegram","whatsapp","slack","teams","zoom","onedrive","epicgameslauncher",
                               "riotclientservices","eadesktop","ealocalhostsvc","eacefsubprocess","nzxt cam",
                               "battle.net","origin","dropbox","notion")
        # İsim + beklenen dizin eşleşmesi (yol içinde geçmesi yeterli, tam eşleşme aranmaz)
        ExpectedPaths     = @{
            svchost  = "C:\Windows\System32"
            lsass    = "C:\Windows\System32"
            csrss    = "C:\Windows\System32"
            wininit  = "C:\Windows\System32"
            services = "C:\Windows\System32"
            explorer = "C:\Windows"
            chrome   = "Google\Chrome\Application"
            msedge   = "Microsoft\Edge\Application"
            firefox  = "Mozilla Firefox"
            discord  = "Discord"
            spotify  = "Spotify"
            steam    = "Steam"
            code     = "Microsoft VS Code"
            telegram = "Telegram Desktop"
            slack    = "slack"
            teams    = "Teams"
            zoom     = "Zoom"
            onedrive = "Microsoft\OneDrive"
        }
        # NOT: Bu liste "bilinmeyen yayıncı = tehlikeli" anlamına gelmez. Geçerli (Valid) bir Authenticode
        # imzası zaten güçlü bir meşruiyet göstergesidir; bu liste yalnızca AppData/Temp altından çalışan
        # imzalı uygulamaları otomatik olarak Düşük risge indirmek için kullanılır.
        TrustedPublishers = @("Microsoft Corporation","Microsoft Windows","Google LLC","Mozilla Corporation",
                               "Discord Inc.","Spotify AB","Valve Corp.","Valve Corporation","Microsoft Windows Publisher",
                               "Telegram FZ-LLC","Telegram Messenger Inc.","Slack Technologies","Zoom Video Communications",
                               "WhatsApp LLC","Electronic Arts","Riot Games","NZXT Inc.","Dropbox, Inc.","Notion Labs, Inc.")
        CriticalPorts     = @(4444,5555,6666,31337,12345,1337,2222,8081)
        SuspiciousParents = @("winword","excel","powerpnt","outlook","mshta","wscript","cscript","equation")
        SuspiciousChildren= @("powershell","pwsh","cmd","wscript","cscript","mshta","regsvr32","rundll32","certutil","bitsadmin")
        GeoIPEnabled      = $true
        GeoIPProvider     = "ip-api"     # "ip-api" (hızlı, toplu, HTTP) veya "ipwho" (HTTPS, tekli sorgu)
        GeoIPTimeoutSec   = 2
        DiscordWebhookUrl = ""
        LogEnabled        = $true
    }
    $defaultConfig | ConvertTo-Json -Depth 6 | Set-Content -Path $ConfigPath -Encoding UTF8
    Write-Host "[*] Varsayılan config oluşturuldu: $ConfigPath" -ForegroundColor DarkGray
    Write-Log "İlk çalışma - varsayılan config oluşturuldu."
}

$config = Get-Content $ConfigPath -Raw | ConvertFrom-Json

# Eski (v3) config dosyalarıyla geriye dönük uyumluluk: eksik alanları tamamla
$needsResave = $false
function Add-MissingConfigField {
    param($cfg, [string]$name, $value)
    if (-not ($cfg.PSObject.Properties.Name -contains $name)) {
        $cfg | Add-Member -NotePropertyName $name -NotePropertyValue $value
        $script:needsResave = $true
    }
}
Add-MissingConfigField $config "ExpectedPaths"      ([PSCustomObject]@{})
Add-MissingConfigField $config "TrustedPublishers"  @()
Add-MissingConfigField $config "SuspiciousParents"  @("winword","excel","powerpnt","outlook","mshta","wscript","cscript")
Add-MissingConfigField $config "SuspiciousChildren" @("powershell","pwsh","cmd","wscript","cscript","mshta","regsvr32","rundll32","certutil","bitsadmin")
Add-MissingConfigField $config "GeoIPProvider"      "ip-api"
Add-MissingConfigField $config "DiscordWebhookUrl"  ""
Add-MissingConfigField $config "LogEnabled"         $true
if ($needsResave) { $config | ConvertTo-Json -Depth 6 | Set-Content -Path $ConfigPath -Encoding UTF8 }

if ($DiscordWebhook) {
    $config.DiscordWebhookUrl = $DiscordWebhook
    $config | ConvertTo-Json -Depth 6 | Set-Content -Path $ConfigPath -Encoding UTF8
    Write-Host "[*] Discord Webhook config'e kaydedildi." -ForegroundColor DarkGray
}

$trustedProcs       = @($config.TrustedProcs)
$expectedPaths      = $config.ExpectedPaths
$trustedPublishers  = @($config.TrustedPublishers)
$criticalPorts      = @($config.CriticalPorts)
$suspiciousParents  = @($config.SuspiciousParents)
$suspiciousChildren = @($config.SuspiciousChildren)
$geoEnabled         = $config.GeoIPEnabled
$geoProvider        = $config.GeoIPProvider
$geoTimeout         = $config.GeoIPTimeoutSec
$discordWebhookUrl  = $config.DiscordWebhookUrl

Write-Host "[*] Config yüklendi. ($($trustedProcs.Count) güvenilir süreç, $($criticalPorts.Count) kritik port)" -ForegroundColor DarkGray
Write-Log "Config yüklendi: $ConfigPath"

# ---------------------------------------------------------------------
# 2) ZAMANLANMIŞ GÖREV KURULUM / KALDIRMA (varsa burada bitir)
# ---------------------------------------------------------------------
$taskName = "SilvaGunlukAgTaramasi"

if ($UninstallScheduledTask) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "[+] Zamanlanmış görev kaldırıldı (varsa)." -ForegroundColor Green
    Exit
}

if ($InstallScheduledTask) {
    $scriptCopy = Join-Path $workDir "silva.ps1"
    try {
        if ($PSCommandPath) { Copy-Item -Path $PSCommandPath -Destination $scriptCopy -Force }
        else { Invoke-WebRequest -Uri $SilvaRawUrl -OutFile $scriptCopy -UseBasicParsing }

        $action  = New-ScheduledTaskAction -Execute "powershell.exe" `
                    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptCopy`" -Silent"
        $trigger = New-ScheduledTaskTrigger -Daily -At "09:00"
        $princ   = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $setting = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
            -Principal $princ -Settings $setting -Description "Silva günlük otomatik ağ güvenlik taraması" -Force | Out-Null

        Write-Host "[+] Zamanlanmış görev kuruldu: her gün 09:00'da sessiz tarama çalışacak." -ForegroundColor Green
        Write-Host "[*] Kaldırmak için: irm $SilvaRawUrl | iex  (sonra -UninstallScheduledTask ile dosyadan çalıştırın)" -ForegroundColor DarkGray
    } catch {
        Write-Host "[-] Zamanlanmış görev kurulamadı: $($_.Exception.Message)" -ForegroundColor Red
    }
    Exit
}

# ---------------------------------------------------------------------
# 3) İLK KURULUM SİHİRBAZI (sadece ilk çalıştırmada + interaktif modda)
# ---------------------------------------------------------------------
if ($isFirstRun -and -not $Silent -and -not $SkipWizard) {
    Write-Host ""
    Write-Host "👋 İlk kez çalıştırıyorsunuz, hızlı bir kurulum yapalım (hepsi opsiyonel, Enter = varsayılan)." -ForegroundColor Cyan

    $wantsDiscord = Read-Host "Kritik bulgularda Discord'a bildirim almak ister misiniz? (e/H)"
    if ($wantsDiscord -match '^[eE]') {
        $wh = Read-Host "Discord Webhook URL'nizi yapıştırın"
        if ($wh) {
            $config.DiscordWebhookUrl = $wh.Trim()
            $discordWebhookUrl = $config.DiscordWebhookUrl
        }
    }

    $wantsSchedule = Read-Host "Her gün otomatik (sessiz) taransın mı? (e/H)"
    if ($wantsSchedule -match '^[eE]') {
        $scriptCopy = Join-Path $workDir "silva.ps1"
        try {
            if ($PSCommandPath) { Copy-Item -Path $PSCommandPath -Destination $scriptCopy -Force }
            else { Invoke-WebRequest -Uri $SilvaRawUrl -OutFile $scriptCopy -UseBasicParsing }
            $action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptCopy`" -Silent"
            $trigger = New-ScheduledTaskTrigger -Daily -At "09:00"
            $princ   = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $princ -Force | Out-Null
            Write-Host "[+] Günlük otomatik tarama kuruldu (09:00)." -ForegroundColor Green
        } catch { Write-Host "[-] Otomatik görev kurulamadı, elle deneyebilirsiniz: -InstallScheduledTask" -ForegroundColor Yellow }
    }

    $config | ConvertTo-Json -Depth 6 | Set-Content -Path $ConfigPath -Encoding UTF8
    Write-Host "[+] Kurulum tamamlandı, tarama başlıyor...`n" -ForegroundColor Green
    Start-Sleep -Seconds 1
}

# ---------------------------------------------------------------------
# 4) KOLAY KULLANIM MENÜSÜ (yalnızca interaktif modda, parametre verilmediyse)
# ---------------------------------------------------------------------
if (-not $Silent -and -not $PSBoundParameters.ContainsKey('DeepScan')) {
    Write-Host ""
    Write-Host "Tarama modunu seçin:" -ForegroundColor Cyan
    Write-Host "  [1] Hızlı Tarama       (varsayılan, ~10-20 sn)"
    Write-Host "  [2] Derin Tarama       (+beacon/C2 davranış tespiti, ~30-40 sn)"
    Write-Host "  [3] Sessiz Mod         (soru sormaz, sadece rapor üretir)"
    $secim = Read-Host "Seçiminiz [1]"
    switch ($secim) {
        "2" { $DeepScan = $true }
        "3" { $Silent = $true }
        default { }
    }
}

# ---------------------------------------------------------------------
# 5) YARDIMCI FONKSİYONLAR
# ---------------------------------------------------------------------
function Resolve-IPBatch {
    param([string[]]$ips, [hashtable]$cache)

    $toQuery = $ips | Where-Object { -not $cache.ContainsKey($_) } | Select-Object -Unique
    if (-not $toQuery -or $toQuery.Count -eq 0) { return }
    if (-not $geoEnabled) {
        foreach ($ip in $toQuery) { $cache[$ip] = "GeoIP Kapalı" }
        return
    }

    if ($geoProvider -eq "ipwho") {
        # HTTPS, tekli sorgu (batch desteklemiyor ama şifreli) - gizliliğe önem verenler için
        foreach ($ip in $toQuery) {
            try {
                $r = Invoke-RestMethod -Uri "https://ipwho.is/$ip" -TimeoutSec $geoTimeout -ErrorAction Stop
                if ($r.success) { $cache[$ip] = "$($r.country) / $($r.connection.isp)" }
                else { $cache[$ip] = "Bilinmiyor" }
            } catch { $cache[$ip] = "Sorgulanamadı (Timeout/Hata)" }
        }
        return
    }

    # Varsayılan: ip-api.com toplu (batch) sorgu - hızlı ama HTTP (şifresiz), ücretsiz katmanda TLS yok
    for ($i = 0; $i -lt $toQuery.Count; $i += 100) {
        $chunk = $toQuery[$i..([Math]::Min($i + 99, $toQuery.Count - 1))]
        $body = ($chunk | ForEach-Object { @{ query = $_; fields = "status,country,isp,query" } }) | ConvertTo-Json
        try {
            $results = Invoke-RestMethod -Uri "http://ip-api.com/batch" -Method Post -Body $body -ContentType "application/json" -TimeoutSec ($geoTimeout * 5) -ErrorAction Stop
            foreach ($r in $results) {
                if ($r.status -eq "success") { $cache[$r.query] = "$($r.country) / $($r.isp)" }
                else { $cache[$r.query] = "Bilinmiyor" }
            }
        } catch {
            foreach ($ip in $chunk) { $cache[$ip] = "Sorgulanamadı (Timeout/Hata)" }
        }
    }
}

function Get-FileSignatureInfo {
    param([string]$path)
    if ($path -eq "-" -or [string]::IsNullOrWhiteSpace($path) -or -not (Test-Path $path -ErrorAction SilentlyContinue)) {
        return [PSCustomObject]@{ IsSigned = $false; Signer = "Dosya Bulunamadı"; Status = "Yok"; IsTrustedPublisher = $false }
    }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
        $isValid = $sig.Status -eq "Valid"
        $signerName = if ($isValid -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject.Split(',')[0] -replace '^CN=','' } else { "İmzasız / Geçersiz" }
        $isTrustedPub = $false
        if ($isValid -and $trustedPublishers.Count -gt 0) {
            foreach ($pub in $trustedPublishers) { if ($signerName -match [regex]::Escape($pub)) { $isTrustedPub = $true; break } }
        }
        return [PSCustomObject]@{ IsSigned = $isValid; Signer = $signerName; Status = $sig.Status.ToString(); IsTrustedPublisher = $isTrustedPub }
    } catch {
        return [PSCustomObject]@{ IsSigned = $false; Signer = "Kontrol Edilemedi"; Status = "Hata"; IsTrustedPublisher = $false }
    }
}

function Test-IsPrivateIP {
    param([string]$ip)
    if ([string]::IsNullOrWhiteSpace($ip)) { return $true }
    if ($ip -match "^127\.|^0\.0\.0\.0$|^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.") { return $true }
    if ($ip -eq "::" -or $ip -eq "::1" -or $ip -match "^fe80:" -or $ip -match "^f[cd][0-9a-f]{2}:") { return $true }
    return $false
}

function Test-TrustedPath {
    # Süreç adı trustedProcs'da ise, dosya yolu beklenen dizinle örtüşüyor mu?
    param([string]$procName, [string]$procPath)
    if ($procPath -eq "-" -or -not $procName) { return $null }  # bilinmiyor
    $expected = $null
    if ($expectedPaths.PSObject.Properties.Name -contains $procName) { $expected = $expectedPaths.$procName }
    if (-not $expected) { return $null }  # bu isim için beklenen yol tanımlı değil
    return ($procPath -match [regex]::Escape($expected))
}

function Test-SuspiciousCommandLine {
    param([string]$cmdLine, [bool]$isTrustedSigner = $false)
    if ([string]::IsNullOrWhiteSpace($cmdLine)) { return $false }

    # Chromium/Electron tabanlı uygulamalar (Discord, Spotify, Slack, NZXT CAM, Steam, tarayıcılar vb.)
    # normalde onlarca alt-süreç (--type=utility/renderer/gpu-process/zygote/crashpad-handler) açar.
    # Bu bayraklar tamamen standarttır ve güvenilir imzalı bir binary için gürültü üretmemelidir.
    if ($isTrustedSigner -and $cmdLine -imatch '--type=(utility|renderer|gpu-process|zygote|crashpad-handler|broker)') {
        return $false
    }

    # Yüksek doğrulukla kötüye kullanım gösteren, dar kapsamlı ve spesifik desenler.
    # Bilinçli olarak "hidden", "bypass" gibi tek başına çok genel kelimeler kullanılmıyor;
    # bunlar meşru uygulamaların komut satırlarında da sıkça rastlanan alt dizgilerdir.
    $patterns = @(
        '-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}',   # -enc/-e ardından gerçek bir base64 blob
        '-window(style)?\s+hidden',                       # açıkça gizli pencere talebi
        '\bfrombase64string\s*\(',
        '\b(net\.webclient)\b.*\bdownloadstring\b',
        'iex\s*\(\s*new-object',
        'mshta(\.exe)?\s+https?://',
        'certutil(\.exe)?\s+.*-decode',
        'bitsadmin(\.exe)?\s+.*\btransfer\b',
        'rundll32(\.exe)?\s+.*javascript:'
    )
    foreach ($p in $patterns) {
        if ($cmdLine -imatch $p) { return $true }
    }
    return $false
}

# ---------------------------------------------------------------------
# 6) SÜREÇ + AĞ BAĞLANTISI TOPLU VERİ TOPLAMA (performans için tek seferde)
# ---------------------------------------------------------------------
Write-Host "[*] Ağ bağlantıları taranıyor..." -ForegroundColor Yellow
$connections = Get-NetTCPConnection -ErrorAction SilentlyContinue
Write-Log "Bağlantı sayısı: $($connections.Count)"

Write-Host "[*] Çalışan süreçler + komut satırları + ebeveyn bilgisi toplanıyor..." -ForegroundColor Yellow
$procTable = @{}
Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procTable[[int]$_.Id] = $_ }

# CIM ile komut satırı ve ebeveyn PID bilgisini tek seferde çek (performans)
$cimTable = @{}
try {
    Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
        $cimTable[[int]$_.ProcessId] = $_
    }
} catch { Write-Log "Win32_Process CIM sorgusu başarısız: $($_.Exception.Message)" "WARN" }

$sigCache = @{}
$geoCache = @{}

# ---------------------------------------------------------------------
# 7) GEOIP TOPLU SORGU
# ---------------------------------------------------------------------
Write-Host "[*] Dış IP'ler toplanıp GeoIP sorgusu yapılıyor..." -ForegroundColor Yellow
$externalIPsToResolve = $connections | ForEach-Object { $_.RemoteAddress } | Where-Object { -not (Test-IsPrivateIP $_) } | Select-Object -Unique
Resolve-IPBatch -ips $externalIPsToResolve -cache $geoCache
Write-Host "[*] $($externalIPsToResolve.Count) benzersiz dış IP sorgulandı." -ForegroundColor DarkGray

# ---------------------------------------------------------------------
# 8) (OPSİYONEL) DERİN TARAMA - BASİT BEACON TESPİTİ
#    Aynı dış IP'ye kısa aralıklarla tekrar bağlantı kuran süreçleri işaretler.
# ---------------------------------------------------------------------
$beaconPorts = @{}  # key: "PID|RemoteIP" -> gözlemlenen FARKLI yerel port'ların kümesi
if ($DeepScan) {
    # Not: Beacon (düzenli C2 check-in) tespiti "bağlantı hâlâ açık mı" sorusuna değil,
    # "süreç aynı uzak IP'ye TEKRAR TEKRAR yeni bağlantı açıyor mu" sorusuna dayanır.
    # Tek, uzun ömürlü bir bağlantının birkaç örneklemede de açık görünmesi (Discord/Spotify/
    # tarayıcı vb. için tamamen normaldir) beacon DEĞİLDİR. Bu yüzden aynı (PID, uzak IP) ikilisi
    # için FARKLI yerel port'ların görülmesini arıyoruz - bu, bağlantının kapanıp yeniden
    # kurulduğunun (gerçek bir "check-in" döngüsünün) kanıtıdır.
    Write-Host "[*] Derin tarama: beacon davranışı için 4 örnekleme yapılıyor (~12 sn)..." -ForegroundColor Yellow
    for ($sample = 1; $sample -le 4; $sample++) {
        $snap = Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Where-Object { -not (Test-IsPrivateIP $_.RemoteAddress) -and $_.OwningProcess -notin @(0,4) }
        foreach ($c in $snap) {
            $key = "$($c.OwningProcess)|$($c.RemoteAddress)"
            if (-not $beaconPorts.ContainsKey($key)) { $beaconPorts[$key] = [System.Collections.Generic.HashSet[int]]::new() }
            [void]$beaconPorts[$key].Add([int]$c.LocalPort)
        }
        if ($sample -lt 4) { Start-Sleep -Seconds 4 }
    }
}

# ---------------------------------------------------------------------
# 9) RİSK ANALİZ MOTORU v4
# ---------------------------------------------------------------------
Write-Host "[*] Risk analizi yürütülüyor (imza + yol + komut satırı + GeoIP zenginleştirmeli)..." -ForegroundColor Yellow

$selfPid = $PID   # Silva'nın kendi PowerShell süreci - kendi "irm | iex" komutu yanlışlıkla şüpheli sayılmasın

$report = foreach ($conn in $connections) {
    $pid_ = [int]$conn.OwningProcess
    if ($pid_ -eq $selfPid) { continue }   # Silva kendi bağlantısını/komut satırını analiz etmez
    $proc = $procTable[$pid_]
    $procName = if ($proc) { $proc.Name } else { "Bilinmiyor" }
    $procPath = if ($proc) { try { $proc.Path } catch { "-" } } else { "-" }
    if (-not $procPath) { $procPath = "-" }

    $cim = $cimTable[$pid_]
    $cmdLine = if ($cim) { $cim.CommandLine } else { "" }
    $parentPid = if ($cim) { [int]$cim.ParentProcessId } else { 0 }
    $parentProc = $procTable[$parentPid]
    $parentName = if ($parentProc) { $parentProc.Name } else { "-" }

    $remoteAddr = $conn.RemoteAddress
    $remotePort = $conn.RemotePort
    $isExternal = -not (Test-IsPrivateIP $remoteAddr)

    $riskStatus = "Normal / Güvenli"
    $riskLevel  = "Düşük"
    $notes      = @()
    $geoInfo    = "Yerel / Yerel Ağ"
    $signerInfo = "-"
    $isSigned   = $null
    $isTrustedPub = $false

    if ($isExternal) {
        $geoInfo = if ($geoCache.ContainsKey($remoteAddr)) { $geoCache[$remoteAddr] } else { "Bilinmiyor" }
    }

    if ($procPath -ne "-") {
        if (-not $sigCache.ContainsKey($procPath)) { $sigCache[$procPath] = Get-FileSignatureInfo -path $procPath }
        $sigResult = $sigCache[$procPath]
        $isSigned = $sigResult.IsSigned
        $signerInfo = $sigResult.Signer
        $isTrustedPub = $sigResult.IsTrustedPublisher
    }

    $pathTrust = Test-TrustedPath -procName $procName -procPath $procPath   # $true / $false / $null
    $cmdSuspicious = Test-SuspiciousCommandLine -cmdLine $cmdLine -isTrustedSigner $isTrustedPub
    $beaconKey = "$pid_|$remoteAddr"
    # En az 2 FARKLI yerel port ile aynı uzak IP'ye bağlanıldıysa gerçek bir yeniden-bağlanma
    # (reconnect) döngüsü var demektir - tek bir açık bağlantı asla bunu tetiklemez.
    $isBeacon = $DeepScan -and $beaconPorts.ContainsKey($beaconKey) -and $beaconPorts[$beaconKey].Count -ge 2

    # --- Karar ağacı (öncelik sırasına göre en kritikten en düşüğe) ---
    if (-not $proc) {
        $riskStatus = "PID Sahipsiz / Kapanmış Süreç"; $riskLevel = "Orta"
    }
    elseif ($criticalPorts -contains $remotePort) {
        $riskStatus = "KRİTİK PORT TESPİT EDİLDİ! (Şüpheli Port: $remotePort)"; $riskLevel = "KRİTİK"
    }
    elseif ($procName -in $trustedProcs -and $pathTrust -eq $false) {
        $riskStatus = "SAHTE SİSTEM/UYGULAMA DOSYASI OLABİLİR! (İsim taklidi - beklenmeyen dizin)"; $riskLevel = "KRİTİK"
    }
    elseif ($suspiciousChildren -contains $procName -and $parentName -in $suspiciousParents) {
        $riskStatus = "OFİS/SCRIPT ENJEKSİYON ZİNCİRİ ŞÜPHESİ! ($parentName -> $procName)"; $riskLevel = "KRİTİK"
    }
    elseif ($cmdSuspicious -and $isExternal) {
        $riskStatus = "ŞÜPHELİ KOMUT SATIRI (obfuscation/indirme/gizli pencere deseni) + dış bağlantı"; $riskLevel = "KRİTİK"
    }
    elseif ($procPath -ne "-" -and $procPath -match "AppData|Temp|Public|Users\\Public|ProgramData" -and $isSigned -eq $false) {
        $riskStatus = "ŞÜPHELİ: Kullanıcı/Temp dizininden çalışan İMZASIZ süreç"; $riskLevel = "KRİTİK"
    }
    elseif ($cmdSuspicious) {
        $riskStatus = "Şüpheli komut satırı deseni tespit edildi"; $riskLevel = "YÜKSEK"
    }
    elseif ($procPath -ne "-" -and $procPath -match "AppData|Temp|Public|Users\\Public|ProgramData") {
        # Not: Discord, Spotify, Telegram, Slack gibi pek çok meşru uygulama BİLEREK AppData altına
        # kurulur (yönetici yetkisi gerektirmemek için). Geçerli bir dijital imza varsa bu durum
        # tek başına Yüksek risk sayılmaz; sadece incelemeye değer (Orta) olarak işaretlenir.
        # Yayıncı ayrıca TrustedPublishers listesindeyse doğrudan Düşük'e iner.
        if ($isTrustedPub) {
            $riskStatus = "AppData/Temp altından çalışıyor ama güvenilir yayıncı tarafından imzalı: $signerInfo"
            $riskLevel = "Düşük"
        } else {
            $riskStatus = "İncelemeye değer: imzalı ama Temp/AppData altından çalışıyor (yayıncı: $signerInfo)"
            $riskLevel = "Orta"
        }
    }
    elseif ($isSigned -eq $false -and $isExternal) {
        $riskStatus = "İMZASIZ program dış ağla konuşuyor"; $riskLevel = "YÜKSEK"
    }
    elseif ($isBeacon) {
        $riskStatus = "OLASI BEACON DAVRANIŞI: aynı dış IP'ye tekrarlayan bağlantı deseni"; $riskLevel = "YÜKSEK"
    }
    elseif ($trustedProcs -notcontains $procName -and $isExternal) {
        $riskLevel = "Orta"; $riskStatus = "Bilinmeyen/Onaylanmamış Program Dış Ağla Konuşuyor"
    }

    if ($isBeacon -and $riskLevel -ne "YÜKSEK" -and $riskLevel -ne "KRİTİK") {
        $notes += "Beacon şüphesi eklendi"
        if ($riskLevel -eq "Orta") { $riskLevel = "YÜKSEK" }
    }

    [PSCustomObject]@{
        "Risk Seviyesi" = $riskLevel
        "Analiz Notu"   = $riskStatus
        "Program Adı"   = $procName
        "Ebeveyn Süreç" = $parentName
        "İmza"          = if ($isSigned -eq $true) { "Geçerli: $signerInfo" } elseif ($isSigned -eq $false) { "İmzasız/Geçersiz" } else { "-" }
        "Yerel Adres"   = "$($conn.LocalAddress):$($conn.LocalPort)"
        "Uzak Adres"    = "$remoteAddr`:$remotePort"
        "Konum/ISP"     = $geoInfo
        "Durum"         = $conn.State
        "PID"           = $pid_
        "Komut Satırı"  = if ($cmdLine.Length -gt 200) { $cmdLine.Substring(0,200) + "..." } else { $cmdLine }
        "Dosya Yolu"    = $procPath
    }
}

# ---------------------------------------------------------------------
# 10) PERSISTENCE (KALICILIK) TARAMASI - Registry + Başlangıç Klasörü + Servisler
# ---------------------------------------------------------------------
Write-Host "[*] Başlangıç kayıtları (Run/RunOnce) taranıyor..." -ForegroundColor Yellow

$persistenceKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

$persistenceReport = foreach ($key in $persistenceKeys) {
    if (Test-Path $key) {
        $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
            [PSCustomObject]@{ "Kayıt Yeri" = $key; "Ad" = $_.Name; "Komut" = $_.Value }
        }
    }
}

Write-Host "[*] Başlangıç klasörleri taranıyor..." -ForegroundColor Yellow
$startupFolders = @(
    [Environment]::GetFolderPath("Startup"),
    [Environment]::GetFolderPath("CommonStartup")
)
$startupReport = foreach ($folder in $startupFolders) {
    if (Test-Path $folder) {
        Get-ChildItem -Path $folder -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{ "Klasör" = $folder; "Dosya" = $_.Name; "DeğişimTarihi" = $_.LastWriteTime }
        }
    }
}

Write-Host "[*] Zamanlanmış görevler taranıyor..." -ForegroundColor Yellow
$scheduledTasksReport = Get-ScheduledTask -ErrorAction SilentlyContinue |
    Where-Object { $_.State -ne "Disabled" -and $_.TaskPath -notmatch "\\Microsoft\\Windows\\" } |
    Select-Object TaskName, TaskPath, State, @{N="Aksiyon";E={($_.Actions.Execute -join "; ")}}

Write-Host "[*] Otomatik başlayan servisler taranıyor (imzasız olanlar işaretlenir)..." -ForegroundColor Yellow
$servicesReport = @()
try {
    $autoServices = Get-CimInstance Win32_Service -Filter "StartMode='Auto'" -ErrorAction Stop |
        Where-Object { $_.PathName -and $_.PathName -notmatch "^C:\\Windows\\System32" }
    foreach ($svc in $autoServices) {
        $exePath = ($svc.PathName -replace '^"?([^"]+\.exe)"?.*$', '$1')
        if (-not $sigCache.ContainsKey($exePath)) { $sigCache[$exePath] = Get-FileSignatureInfo -path $exePath }
        $sig = $sigCache[$exePath]
        $servicesReport += [PSCustomObject]@{
            "Servis Adı" = $svc.Name
            "Görünen Ad" = $svc.DisplayName
            "Yol"        = $svc.PathName
            "İmza"       = if ($sig.IsSigned) { "Geçerli: $($sig.Signer)" } else { "İMZASIZ/GEÇERSİZ" }
        }
    }
} catch { Write-Log "Win32_Service sorgusu başarısız: $($_.Exception.Message)" "WARN" }

# ---------------------------------------------------------------------
# 11) GEÇMİŞLE KARŞILAŞTIRMA (yeni IP tespiti)
# ---------------------------------------------------------------------
$currentExternalIPs = $report | Where-Object { $_."Konum/ISP" -notmatch "^Yerel" -and $_."Uzak Adres" -notmatch "^0\.0\.0\.0|^127\." } |
    ForEach-Object { ($_."Uzak Adres" -split ':')[0] } | Select-Object -Unique

$newIPs = @()
if (Test-Path $historyPath) {
    $prevHistory = Get-Content $historyPath -Raw | ConvertFrom-Json
    $prevIPs = @($prevHistory.KnownIPs)
    $newIPs = $currentExternalIPs | Where-Object { $_ -notin $prevIPs }
} else {
    Write-Host "[*] İlk çalıştırma - geçmiş kaydı oluşturuluyor." -ForegroundColor DarkGray
}

@{ KnownIPs = $currentExternalIPs; LastRun = (Get-Date).ToString(); Version = $SilvaVersion } |
    ConvertTo-Json | Set-Content -Path $historyPath -Encoding UTF8

if ($newIPs.Count -gt 0) {
    Write-Host "[!] Önceki taramada görülmeyen $($newIPs.Count) yeni dış IP tespit edildi:" -ForegroundColor Magenta
    $newIPs | ForEach-Object { Write-Host "    -> $_" -ForegroundColor Magenta }
}

# ---------------------------------------------------------------------
# 12) RAPORLARI DIŞA AKTAR (CSV + HTML + JSON)
# ---------------------------------------------------------------------
$desktop  = [Environment]::GetFolderPath("Desktop")
$htmlPath = Join-Path $desktop "Silva_Ag_Guvenlik_Raporu.html"
$csvPath  = Join-Path $desktop "Silva_Ag_Guvenlik_Raporu.csv"
$jsonPath = Join-Path $desktop "Silva_Ag_Guvenlik_Raporu.json"

if ($ExportFormat -in @("CSV","All"))  { $report | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8 }
if ($ExportFormat -in @("JSON","All")) {
    @{
        OlusturmaZamani = (Get-Date).ToString("o")
        Surum           = $SilvaVersion
        Ozet            = @{
            Toplam  = $report.Count
            Kritik  = ($report | Where-Object { $_."Risk Seviyesi" -eq "KRİTİK" }).Count
            Yuksek  = ($report | Where-Object { $_."Risk Seviyesi" -eq "YÜKSEK" }).Count
            Orta    = ($report | Where-Object { $_."Risk Seviyesi" -eq "Orta" }).Count
            YeniIP  = $newIPs.Count
        }
        Baglantilar     = $report
        Kalicilik       = @{ Registry = $persistenceReport; Baslangic = $startupReport; Gorevler = $scheduledTasksReport; Servisler = $servicesReport }
        YeniIPler       = $newIPs
    } | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8
}

if ($ExportFormat -in @("HTML","All")) {
$htmlHeader = @"
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Silva Ağ Güvenlik Raporu</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #1e1e1e; color: #d4d4d4; margin: 20px; }
        h2 { color: #4ec9b0; }
        h3 { color: #9cdcfe; margin-top: 40px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; background-color: #252526; }
        th, td { padding: 9px; border: 1px solid #3f3f46; text-align: left; font-size: 13px; word-break: break-word; }
        th { background-color: #333333; color: #4ec9b0; position: sticky; top: 0; }
        tr:hover { background-color: #2a2d2e; }
        .KRİTİK { background-color: #510000; color: #ff5555; font-weight: bold; }
        .YÜKSEK { background-color: #4d2600; color: #ffaa00; font-weight: bold; }
        .Orta   { background-color: #4d4d00; color: #ffff55; }
        .Düşük  { color: #55ff55; }
        .newip  { color: #ff77ff; font-weight: bold; }
        .summary { display: flex; gap: 20px; margin-top: 15px; flex-wrap: wrap; }
        .summary div { background: #252526; padding: 12px 20px; border-radius: 6px; border: 1px solid #3f3f46; }
    </style>
</head>
<body>
    <h2>🛡 Silva v$SilvaVersion - Ağ Güvenlik ve Risk Analiz Paneli</h2>
    <p>Rapor Oluşturma Zamanı: $(Get-Date)</p>
    <div class="summary">
        <div>Toplam Bağlantı: <b>$($report.Count)</b></div>
        <div style="color:#ff5555">Kritik: <b>$(($report | Where-Object {$_."Risk Seviyesi" -eq "KRİTİK"}).Count)</b></div>
        <div style="color:#ffaa00">Yüksek: <b>$(($report | Where-Object {$_."Risk Seviyesi" -eq "YÜKSEK"}).Count)</b></div>
        <div style="color:#ffff55">Orta: <b>$(($report | Where-Object {$_."Risk Seviyesi" -eq "Orta"}).Count)</b></div>
        <div class="newip">Yeni Dış IP: $($newIPs.Count)</div>
    </div>
    <table>
        <tr>
            <th>Risk</th><th>Analiz Notu</th><th>Program</th><th>Ebeveyn</th><th>İmza</th>
            <th>Yerel Adres</th><th>Uzak Adres</th><th>Konum/ISP</th>
            <th>Durum</th><th>PID</th><th>Komut Satırı</th><th>Dosya Yolu</th>
        </tr>
"@

    $htmlRows = foreach ($row in $report) {
        $cls = $row."Risk Seviyesi"
        "<tr class='$cls'>
            <td>$($row."Risk Seviyesi")</td>
            <td>$($row."Analiz Notu")</td>
            <td>$($row."Program Adı")</td>
            <td>$($row."Ebeveyn Süreç")</td>
            <td>$($row."İmza")</td>
            <td>$($row."Yerel Adres")</td>
            <td>$($row."Uzak Adres")</td>
            <td>$($row."Konum/ISP")</td>
            <td>$($row."Durum")</td>
            <td>$($row."PID")</td>
            <td>$($row."Komut Satırı")</td>
            <td>$($row."Dosya Yolu")</td>
        </tr>"
    }

    $persistenceHtml = "<h3>🔁 Başlangıç Kayıtları (Run/RunOnce)</h3><table><tr><th>Kayıt Yeri</th><th>Ad</th><th>Komut</th></tr>"
    foreach ($p in $persistenceReport) { $persistenceHtml += "<tr><td>$($p.'Kayıt Yeri')</td><td>$($p.Ad)</td><td>$($p.Komut)</td></tr>" }
    $persistenceHtml += "</table>"

    $startupHtml = "<h3>📁 Başlangıç Klasörü</h3><table><tr><th>Klasör</th><th>Dosya</th><th>Değişim Tarihi</th></tr>"
    foreach ($s in $startupReport) { $startupHtml += "<tr><td>$($s.'Klasör')</td><td>$($s.Dosya)</td><td>$($s.DeğişimTarihi)</td></tr>" }
    $startupHtml += "</table>"

    $tasksHtml = "<h3>⏱ Zamanlanmış Görevler (Microsoft dışı)</h3><table><tr><th>Ad</th><th>Yol</th><th>Durum</th><th>Aksiyon</th></tr>"
    foreach ($t in $scheduledTasksReport) { $tasksHtml += "<tr><td>$($t.TaskName)</td><td>$($t.TaskPath)</td><td>$($t.State)</td><td>$($t.Aksiyon)</td></tr>" }
    $tasksHtml += "</table>"

    $servicesHtml = "<h3>⚙ Otomatik Başlayan Servisler (System32 dışı)</h3><table><tr><th>Servis Adı</th><th>Görünen Ad</th><th>Yol</th><th>İmza</th></tr>"
    foreach ($sv in $servicesReport) { $servicesHtml += "<tr><td>$($sv.'Servis Adı')</td><td>$($sv.'Görünen Ad')</td><td>$($sv.Yol)</td><td>$($sv.'İmza')</td></tr>" }
    $servicesHtml += "</table>"

    $htmlFooter = "</table>$persistenceHtml$startupHtml$tasksHtml$servicesHtml</body></html>"
    Set-Content -Path $htmlPath -Value ($htmlHeader + $htmlRows + $htmlFooter) -Encoding UTF8
}

Write-Host "`n[+] Analiz Tamamlandı!" -ForegroundColor Green
if ($ExportFormat -in @("HTML","All")) { Write-Host "[*] HTML Raporu : $htmlPath" -ForegroundColor Yellow }
if ($ExportFormat -in @("CSV","All"))  { Write-Host "[*] CSV Raporu  : $csvPath" -ForegroundColor Yellow }
if ($ExportFormat -in @("JSON","All")) { Write-Host "[*] JSON Raporu : $jsonPath" -ForegroundColor Yellow }
Write-Log "Rapor üretildi. Toplam=$($report.Count) Kritik=$(($report | Where-Object {$_.'Risk Seviyesi' -eq 'KRİTİK'}).Count)"

# ---------------------------------------------------------------------
# 13) DISCORD WEBHOOK BİLDİRİMİ (opsiyonel, ücretsiz)
# ---------------------------------------------------------------------
$kritikSayisi = ($report | Where-Object { $_."Risk Seviyesi" -eq "KRİTİK" }).Count
$yuksekSayisi = ($report | Where-Object { $_."Risk Seviyesi" -eq "YÜKSEK" }).Count

if ($discordWebhookUrl -and ($kritikSayisi -gt 0 -or $yuksekSayisi -gt 0 -or $newIPs.Count -gt 0)) {
    try {
        $bilgisayarAdi = $env:COMPUTERNAME
        $ozetSatirlari = ($report | Where-Object { $_."Risk Seviyesi" -in @("KRİTİK","YÜKSEK") } |
            Select-Object -First 5 | ForEach-Object { "• [$($_.'Risk Seviyesi')] $($_.'Program Adı') -> $($_.'Uzak Adres') ($($_.'Analiz Notu'))" }) -join "`n"
        if (-not $ozetSatirlari) { $ozetSatirlari = "Kritik/Yüksek bulgu yok, sadece yeni IP tespiti var." }

        $payload = @{
            embeds = @(@{
                title       = "🛡 Silva Güvenlik Uyarısı - $bilgisayarAdi"
                description = "Kritik: **$kritikSayisi** · Yüksek: **$yuksekSayisi** · Yeni Dış IP: **$($newIPs.Count)**`n`n$ozetSatirlari"
                color       = if ($kritikSayisi -gt 0) { 15548997 } else { 16750899 }
                timestamp   = (Get-Date).ToString("o")
            })
        } | ConvertTo-Json -Depth 6

        Invoke-RestMethod -Uri $discordWebhookUrl -Method Post -Body $payload -ContentType "application/json" -ErrorAction Stop | Out-Null
        Write-Host "[*] Discord bildirimi gönderildi." -ForegroundColor DarkGray
        Write-Log "Discord webhook bildirimi gönderildi."
    } catch {
        Write-Host "[-] Discord bildirimi gönderilemedi: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log "Discord webhook hatası: $($_.Exception.Message)" "WARN"
    }
}

# ---------------------------------------------------------------------
# 14) İNTERAKTİF SÜREÇ SONLANDIRMA (Sessiz modda atlanır)
# ---------------------------------------------------------------------
$kritikKayitlar = $report | Where-Object { $_."Risk Seviyesi" -in @("KRİTİK","YÜKSEK") }

if ($kritikKayitlar -and -not $Silent) {
    Write-Host "`n[!] DİKKAT: Sistemde yüksek riskli veya kritik seviyede süreçler tespit edildi!" -ForegroundColor Red
    $kritikKayitlar | Select-Object "Risk Seviyesi","Program Adı","PID","Analiz Notu" -Unique | Format-Table -AutoSize

    $secim2 = Read-Host "`nSonlandırmak istediğiniz PID'leri virgülle ayırarak yazın (örn: 1234,5678) veya Enter'a basıp geçin"

    if (-not [string]::IsNullOrWhiteSpace($secim2)) {
        $pids = $secim2 -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
        foreach ($pidToKill in $pids) {
            try {
                Stop-Process -Id $pidToKill -Force -ErrorAction Stop
                Write-Host "[+] $pidToKill PID numaralı süreç başarıyla sonlandırıldı." -ForegroundColor Green
                Write-Log "Süreç sonlandırıldı: PID $pidToKill"
            } catch {
                Write-Host "[-] $pidToKill PID sonlandırılamadı: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
} elseif ($kritikKayitlar -and $Silent) {
    Write-Log "Sessiz modda $($kritikKayitlar.Count) kritik/yüksek bulgu tespit edildi, müdahale yapılmadı."
}

# ---------------------------------------------------------------------
# 15) GÖRSEL LİSTE (Out-GridView) - sessiz modda atlanır
# ---------------------------------------------------------------------
if (-not $Silent) {
    $gridAvailable = Get-Command Out-GridView -ErrorAction SilentlyContinue
    if ($gridAvailable) {
        $report | Out-GridView -Title "Silva v$SilvaVersion - Ağ ve Risk Analiz Raporu"
    } else {
        Write-Host "[*] Out-GridView bu sistemde mevcut değil, sonuçları HTML/CSV raporundan inceleyebilirsiniz." -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------
# 16) ÇIKIŞ KODU (otomasyon / SIEM entegrasyonu için)
# ---------------------------------------------------------------------
Write-Log "Tarama tamamlandı. Çıkış kodu belirleniyor."
if ($kritikSayisi -gt 0) { exit 2 }
elseif ($yuksekSayisi -gt 0) { exit 1 }
else { exit 0 }
