# =====================================================================
#   SİLVA - GELİŞMİŞ AKILLI AĞ GÜVENLİĞİ VE RİSK ANALİZ ARACI v3.0
#   - Dijital imza doğrulaması
#   - GeoIP / ISP zenginleştirme (cache'li)
#   - Performans: toplu process/ağ tarama
#   - Persistence (kalıcılık) taraması
#   - Geçmişle karşılaştırma (yeni IP/süreç tespiti)
#   - Dış config dosyası (whitelist / kritik portlar)
# =====================================================================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

Clear-Host
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "     SİLVA v3.0 - GELİŞMİŞ AĞ GÜVENLİK ANALİZİ    " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# ---------------------------------------------------------------------
# 0) ÇALIŞMA DİZİNİ VE CONFIG YÖNETİMİ
# ---------------------------------------------------------------------
$workDir    = Join-Path $env:LOCALAPPDATA "Silva"
$configPath = Join-Path $workDir "config.json"
$historyPath= Join-Path $workDir "history.json"

if (-not (Test-Path $workDir)) { New-Item -ItemType Directory -Path $workDir | Out-Null }

if (-not (Test-Path $configPath)) {
    $defaultConfig = @{
        TrustedProcs  = @("svchost","lsass","csrss","wininit","services","explorer","chrome",
                           "firefox","msedge","discord","spotify","steam","code","powershell","cmd")
        CriticalPorts = @(4444,5555,6666,31337,12345)
        GeoIPEnabled  = $true
        GeoIPTimeoutSec = 2
    }
    $defaultConfig | ConvertTo-Json -Depth 5 | Set-Content -Path $configPath -Encoding UTF8
    Write-Host "[*] Varsayılan config oluşturuldu: $configPath" -ForegroundColor DarkGray
}

$config = Get-Content $configPath -Raw | ConvertFrom-Json
$trustedProcs  = $config.TrustedProcs
$criticalPorts = $config.CriticalPorts
$geoEnabled    = $config.GeoIPEnabled
$geoTimeout    = $config.GeoIPTimeoutSec

Write-Host "[*] Config yüklendi. ($($trustedProcs.Count) güvenilir süreç, $($criticalPorts.Count) kritik port)" -ForegroundColor DarkGray

# ---------------------------------------------------------------------
# 1) YARDIMCI FONKSİYONLAR
# ---------------------------------------------------------------------

function Get-IPInfoCached {
    param([string]$ip, [hashtable]$cache)
    if ($cache.ContainsKey($ip)) { return $cache[$ip] }

    $result = "Sorgulanamadı"
    if ($geoEnabled) {
        try {
            $r = Invoke-RestMethod -Uri "http://ip-api.com/json/$ip?fields=status,country,isp,query" -TimeoutSec $geoTimeout -ErrorAction Stop
            if ($r.status -eq "success") {
                $result = "$($r.country) / $($r.isp)"
            } else {
                $result = "Bilinmiyor"
            }
        } catch {
            $result = "Sorgulanamadı (Timeout/Hata)"
        }
    } else {
        $result = "GeoIP Kapalı"
    }
    $cache[$ip] = $result
    return $result
}

function Get-FileSignatureInfo {
    param([string]$path)
    if ($path -eq "-" -or [string]::IsNullOrWhiteSpace($path) -or -not (Test-Path $path -ErrorAction SilentlyContinue)) {
        return [PSCustomObject]@{ IsSigned = $false; Signer = "Dosya Bulunamadı"; Status = "Yok" }
    }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
        $isValid = $sig.Status -eq "Valid"
        $signerName = if ($isValid -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject.Split(',')[0] -replace '^CN=','' } else { "İmzasız / Geçersiz" }
        return [PSCustomObject]@{ IsSigned = $isValid; Signer = $signerName; Status = $sig.Status.ToString() }
    } catch {
        return [PSCustomObject]@{ IsSigned = $false; Signer = "Kontrol Edilemedi"; Status = "Hata" }
    }
}

function Test-IsPrivateIP {
    param([string]$ip)
    return ($ip -match "^127\.|^0\.0\.0\.0$|^::1$|^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.")
}

# ---------------------------------------------------------------------
# 2) AĞ BAĞLANTILARI + SÜREÇLERİ TOPLU ÇEK (performans)
# ---------------------------------------------------------------------
Write-Host "[*] Ağ bağlantıları taranıyor..." -ForegroundColor Yellow
$connections = Get-NetTCPConnection -ErrorAction SilentlyContinue

Write-Host "[*] Çalışan süreçler önbelleğe alınıyor..." -ForegroundColor Yellow
$procTable = @{}
Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procTable[$_.Id] = $_ }

$sigCache = @{}
$geoCache = @{}

# ---------------------------------------------------------------------
# 3) RİSK ANALİZ MOTORU v3
# ---------------------------------------------------------------------
Write-Host "[*] Risk analizi yürütülüyor (imza + GeoIP zenginleştirmeli)..." -ForegroundColor Yellow

$report = foreach ($conn in $connections) {
    $proc = $procTable[$conn.OwningProcess]
    $procName = if ($proc) { $proc.Name } else { "Bilinmiyor" }
    $procPath = if ($proc) { try { $proc.Path } catch { "-" } } else { "-" }
    if (-not $procPath) { $procPath = "-" }

    $remoteAddr = $conn.RemoteAddress
    $remotePort = $conn.RemotePort
    $isExternal = -not (Test-IsPrivateIP $remoteAddr)

    $riskStatus = "Normal / Güvenli"
    $riskLevel  = "Düşük"
    $geoInfo    = "Yerel / Yerel Ağ"
    $signerInfo = "-"
    $isSigned   = $null

    if ($isExternal) {
        $geoInfo = Get-IPInfoCached -ip $remoteAddr -cache $geoCache
    }

    # İmza kontrolü (sadece dosya yolu bulunan süreçler için, cache'li)
    if ($procPath -ne "-") {
        if (-not $sigCache.ContainsKey($procPath)) {
            $sigCache[$procPath] = Get-FileSignatureInfo -path $procPath
        }
        $sigResult = $sigCache[$procPath]
        $isSigned = $sigResult.IsSigned
        $signerInfo = $sigResult.Signer
    }

    # --- Karar ağacı ---
    if (-not $proc) {
        $riskStatus = "PID Sahipsiz / Kapanmış Süreç"
        $riskLevel = "Orta"
    }
    elseif ($criticalPorts -contains $remotePort) {
        $riskStatus = "KRİTİK PORT TESPİT EDİLDİ! (Şüpheli Port: $remotePort)"
        $riskLevel = "KRİTİK"
    }
    elseif ($procPath -ne "-" -and $procName -in @("svchost","lsass","explorer","csrss","wininit") -and $procPath -notmatch "C:\\Windows\\System32|C:\\Windows\\") {
        $riskStatus = "SAHTE SİSTEM DOSYASI OLABİLİR! (İsim taklidi)"
        $riskLevel = "KRİTİK"
    }
    elseif ($procPath -ne "-" -and $procPath -match "AppData|Temp|Public|Users\\Public|ProgramData" -and $isSigned -eq $false) {
        $riskStatus = "ŞÜPHELİ: Kullanıcı/Temp dizininden çalışan İMZASIZ süreç"
        $riskLevel = "KRİTİK"
    }
    elseif ($procPath -ne "-" -and $procPath -match "AppData|Temp|Public|Users\\Public|ProgramData") {
        $riskStatus = "ŞÜPHELİ DİZİN (imzalı ama Temp/AppData altından çalışıyor)"
        $riskLevel = "YÜKSEK"
    }
    elseif ($isSigned -eq $false -and $isExternal) {
        $riskStatus = "İMZASIZ program dış ağla konuşuyor"
        $riskLevel = "YÜKSEK"
    }
    elseif ($trustedProcs -notcontains $procName -and $isExternal) {
        $riskLevel = "Orta"
        $riskStatus = "Bilinmeyen/Onaylanmamış Program Dış Ağla Konuşuyor"
    }

    [PSCustomObject]@{
        "Risk Seviyesi" = $riskLevel
        "Analiz Notu"   = $riskStatus
        "Program Adı"   = $procName
        "İmza"          = if ($isSigned -eq $true) { "Geçerli: $signerInfo" } elseif ($isSigned -eq $false) { "İmzasız/Geçersiz" } else { "-" }
        "Yerel Adres"   = "$($conn.LocalAddress):$($conn.LocalPort)"
        "Uzak Adres"    = "$remoteAddr`:$remotePort"
        "Konum/ISP"     = $geoInfo
        "Durum"         = $conn.State
        "PID"           = $conn.OwningProcess
        "Dosya Yolu"    = $procPath
    }
}

# ---------------------------------------------------------------------
# 4) PERSISTENCE (KALICILIK) TARAMASI
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
            [PSCustomObject]@{
                "Kayıt Yeri" = $key
                "Ad"         = $_.Name
                "Komut"      = $_.Value
            }
        }
    }
}

$scheduledTasksReport = Get-ScheduledTask -ErrorAction SilentlyContinue |
    Where-Object { $_.State -ne "Disabled" -and $_.TaskPath -notmatch "\\Microsoft\\Windows\\" } |
    Select-Object TaskName, TaskPath, State, @{N="Aksiyon";E={($_.Actions.Execute -join "; ")}}

# ---------------------------------------------------------------------
# 5) GEÇMİŞLE KARŞILAŞTIRMA (yeni IP / yeni süreç tespiti)
# ---------------------------------------------------------------------
$currentExternalIPs = $report | Where-Object { $_."Konum/ISP" -match "^(?!Yerel)" -and $_."Uzak Adres" -notmatch "^0\.0\.0\.0|^127\." } |
    Select-Object -ExpandProperty "Uzak Adres" -Unique

$newIPs = @()
if (Test-Path $historyPath) {
    $prevHistory = Get-Content $historyPath -Raw | ConvertFrom-Json
    $prevIPs = @($prevHistory.KnownIPs)
    $newIPs = $currentExternalIPs | Where-Object { $_ -notin $prevIPs }
} else {
    Write-Host "[*] İlk çalıştırma - geçmiş kaydı oluşturuluyor." -ForegroundColor DarkGray
}

@{ KnownIPs = $currentExternalIPs; LastRun = (Get-Date).ToString() } | ConvertTo-Json | Set-Content -Path $historyPath -Encoding UTF8

if ($newIPs.Count -gt 0) {
    Write-Host "[!] Önceki taramada görülmeyen $($newIPs.Count) yeni dış IP tespit edildi:" -ForegroundColor Magenta
    $newIPs | ForEach-Object { Write-Host "    -> $_" -ForegroundColor Magenta }
}

# ---------------------------------------------------------------------
# 6) RAPORLARI DIŞA AKTAR (CSV + HTML)
# ---------------------------------------------------------------------
$desktop = [Environment]::GetFolderPath("Desktop")
$htmlPath = Join-Path $desktop "Silva_Ag_Guvenlik_Raporu.html"
$csvPath  = Join-Path $desktop "Silva_Ag_Guvenlik_Raporu.csv"

$report | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8

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
        .badge  { padding: 2px 8px; border-radius: 4px; font-size: 12px; }
        .newip  { color: #ff77ff; font-weight: bold; }
        .summary { display: flex; gap: 20px; margin-top: 15px; }
        .summary div { background: #252526; padding: 12px 20px; border-radius: 6px; border: 1px solid #3f3f46; }
    </style>
</head>
<body>
    <h2>🛡 Silva v3.0 - Ağ Güvenlik ve Risk Analiz Paneli</h2>
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
            <th>Risk</th><th>Analiz Notu</th><th>Program</th><th>İmza</th>
            <th>Yerel Adres</th><th>Uzak Adres</th><th>Konum/ISP</th>
            <th>Durum</th><th>PID</th><th>Dosya Yolu</th>
        </tr>
"@

$htmlRows = foreach ($row in $report) {
    $cls = $row."Risk Seviyesi" -replace "İ","İ"
    "<tr class='$cls'>
        <td>$($row."Risk Seviyesi")</td>
        <td>$($row."Analiz Notu")</td>
        <td>$($row."Program Adı")</td>
        <td>$($row."İmza")</td>
        <td>$($row."Yerel Adres")</td>
        <td>$($row."Uzak Adres")</td>
        <td>$($row."Konum/ISP")</td>
        <td>$($row."Durum")</td>
        <td>$($row."PID")</td>
        <td>$($row."Dosya Yolu")</td>
    </tr>"
}

$persistenceHtml = "<h3>🔁 Başlangıç Kayıtları (Run/RunOnce)</h3><table><tr><th>Kayıt Yeri</th><th>Ad</th><th>Komut</th></tr>"
foreach ($p in $persistenceReport) {
    $persistenceHtml += "<tr><td>$($p.'Kayıt Yeri')</td><td>$($p.Ad)</td><td>$($p.Komut)</td></tr>"
}
$persistenceHtml += "</table>"

$tasksHtml = "<h3>⏱ Zamanlanmış Görevler (Microsoft dışı)</h3><table><tr><th>Ad</th><th>Yol</th><th>Durum</th><th>Aksiyon</th></tr>"
foreach ($t in $scheduledTasksReport) {
    $tasksHtml += "<tr><td>$($t.TaskName)</td><td>$($t.TaskPath)</td><td>$($t.State)</td><td>$($t.Aksiyon)</td></tr>"
}
$tasksHtml += "</table>"

$htmlFooter = "</table>$persistenceHtml$tasksHtml</body></html>"
Set-Content -Path $htmlPath -Value ($htmlHeader + $htmlRows + $htmlFooter) -Encoding UTF8

Write-Host "`n[+] Analiz Tamamlandı!" -ForegroundColor Green
Write-Host "[*] HTML Raporu: $htmlPath" -ForegroundColor Yellow
Write-Host "[*] CSV Raporu : $csvPath" -ForegroundColor Yellow

# ---------------------------------------------------------------------
# 7) İNTERAKTİF SÜREÇ SONLANDIRMA (çoklu PID desteği)
# ---------------------------------------------------------------------
$kritikKayitlar = $report | Where-Object { $_."Risk Seviyesi" -in @("KRİTİK","YÜKSEK") }

if ($kritikKayitlar) {
    Write-Host "`n[!] DİKKAT: Sistemde yüksek riskli veya kritik seviyede süreçler tespit edildi!" -ForegroundColor Red
    $kritikKayitlar | Select-Object "Risk Seviyesi","Program Adı","PID","Analiz Notu" -Unique | Format-Table -AutoSize

    $secim = Read-Host "`nSonlandırmak istediğiniz PID'leri virgülle ayırarak yazın (örn: 1234,5678) veya Enter'a basıp geçin"

    if (-not [string]::IsNullOrWhiteSpace($secim)) {
        $pids = $secim -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
        foreach ($pidToKill in $pids) {
            try {
                Stop-Process -Id $pidToKill -Force -ErrorAction Stop
                Write-Host "[+] $pidToKill PID numaralı süreç başarıyla sonlandırıldı." -ForegroundColor Green
            } catch {
                Write-Host "[-] $pidToKill PID sonlandırılamadı: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}

# ---------------------------------------------------------------------
# 8) GÖRSEL LİSTE (Out-GridView)
# ---------------------------------------------------------------------
$report | Out-GridView -Title "Silva v3.0 - Ağ ve Risk Analiz Raporu"
