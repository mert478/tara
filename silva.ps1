# =====================================================================
#   SİLVA - GELİŞMİŞ AKILLI AĞ GÜVENLİĞİ VE RİSK ANALİZ ARACI v2.0
# =====================================================================

# Konsol ve karakter kodlamasını UTF-8 yap
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

# Yönetici yetkisi kontrolü ve otomatik yükseltme
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

Clear-Host
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "     SİLVA - GELİŞMİŞ AĞ GÜVENLİK ANALİZİ         " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "[*] Ağ bağlantıları, PID'ler ve dosya yolları taranıyor..." -ForegroundColor Yellow

$connections = Get-NetTCPConnection -ErrorAction SilentlyContinue

# Güvenilir sistem süreçleri listesi
$trustedProcs = @("svchost", "lsass", "csrss", "wininit", "services", "explorer", "chrome", "firefox", "msedge", "discord", "spotify", "steam", "code", "NGENUITY", "NZXT CAM", "EABackgroundService", "GameManagerService3", "powershell", "cmd")

# Kritik/Zararlı olabilecek yaygın portlar
$criticalPorts = @(4444, 5555, 6666, 31337, 12345)

$report = foreach ($conn in $connections) {
    $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
    
    $procName = if ($proc) { $proc.Name } else { "Bilinmiyor" }
    $procPath = if ($proc) { $proc.Path } else { "-" }
    $remoteAddr = $conn.RemoteAddress
    $remotePort = $conn.RemotePort
    
    # --- RİSK ANALİZ MOTORU v2 ---
    $riskStatus = "Normal / Güvenli"
    $riskLevel = "Düşük"
    $geoInfo = "Yerel / Yerel Ağ"

    # Harici IP tespiti ve basit konum/lokasyon simülasşyonu (Dış IP sorgusu)
    if ($remoteAddr -notmatch "127\.0\.0\.1|0\.0\.0\.0|::1|^192\.168\.|^10\.|^172\.") {
        $geoInfo = "Harici IP ($remoteAddr)"
    }

    if (-not $proc) {
        $riskStatus = "PID Sahipsiz / Kapanmış Süreç"
        $riskLevel = "Orta"
    }
    elseif ($criticalPorts -contains $remotePort) {
        $riskStatus = "KRİTİK PORT TESPİT EDİLDİ! (Şüpheli Port: $remotePort)"
        $riskLevel = "KRİTİK"
    }
    elseif ($procPath -ne "-") {
        if ($procPath -match "AppData|Temp|Public|Users\\Public|ProgramData") {
            $riskStatus = "ŞÜPHELİ DİZİN! (Kullanıcı alanı/Temp altından çalışıyor)"
            $riskLevel = "YÜKSEK"
        }
        elseif ($procName -in @("svchost", "lsass", "explorer") -and $procPath -notmatch "C:\\Windows\\System32|C:\\Windows\\") {
            $riskStatus = "SAHTE SİSTEM DOSYASI OLABİLİR!"
            $riskLevel = "KRİTİK"
        }
        elseif ($trustedProcs -notcontains $procName -and $geoInfo -match "Harici IP") {
            $riskLevel = "Orta"
            $riskStatus = "Bilinmeyen Program Dış Ağla Konuşuyor"
        }
    }

    [PSCustomObject]@{
        "Risk Seviyesi" = $riskLevel
        "Analiz Notu"   = $riskStatus
        "Program Adı"   = $procName
        "Yerel Adres"   = "$($conn.LocalAddress):$($conn.LocalPort)"
        "Uzak Adres"    = "$remoteAddr`:$remotePort"
        "Bağlantı Tipi" = $geoInfo
        "Durum"         = $conn.State
        "PID"           = $conn.OwningProcess
        "Dosya Yolu"    = $procPath
    }
}

# Raporu masaüstüne kaydet (CSV ve HTML)
$desktop = [Environment]::GetFolderPath("Desktop")
$htmlPath = Join-Path $desktop "Silva_Ag_Guvenlik_Raporu.html"
$csvPath = Join-Path $desktop "Silva_Ag_Guvenlik_Raporu.csv"

$report | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8

# Modern ve Şık HTML Tasarımı Oluşturma
$htmlHeader = @"
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Silva Ağ Güvenlik Raporu</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #1e1e1e; color: #d4d4d4; margin: 20px; }
        h2 { color: #4ec9b0; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background-color: #252526; }
        th, td { padding: 10px; border: 1px solid #3f3f46; text-align: left; font-size: 14px; }
        th { background-color: #333333; color: #4ec9b0; }
        tr:hover { background-color: #2a2d2e; }
        .KRİTİK { background-color: #510000; color: #ff5555; font-weight: bold; }
        .YUKSEK { background-color: #4d2600; color: #ffaa00; font-weight: bold; }
        .Orta { background-color: #4d4d00; color: #ffff55; }
        .Düşük { color: #55ff55; }
    </style>
</head>
<body>
    <h2>Silva - Gelişmiş Ağ Güvenlik ve Risk Analiz Paneli</h2>
    <p>Rapor Oluşturma Zamanı: $(Get-Date)</p>
    <table>
        <tr>
            <th>Risk Seviyesi</th>
            <th>Analiz Notu</th>
            <th>Program Adı</th>
            <th>Yerel Adres</th>
            <th>Uzak Adres</th>
            <th>Durum</th>
            <th>PID</th>
            <th>Dosya Yolu</th>
        </tr>
"@

$htmlRows = foreach ($row in $report) {
    "<tr class='$($row."Risk Seviyesi")'>
        <td>$($row."Risk Seviyesi")</td>
        <td>$($row."Analiz Notu")</td>
        <td>$($row."Program Adı")</td>
        <td>$($row."Yerel Adres")</td>
        <td>$($row."Uzak Adres")</td>
        <td>$($row."Durum")</td>
        <td>$($row."PID")</td>
        <td>$($row."Dosya Yolu")</td>
    </tr>"
}

$htmlFooter = "</table></body></html>"
Set-Content -Path $htmlPath -Value ($htmlHeader + $htmlRows + $htmlFooter) -Encoding UTF8

Write-Host "`n[+] Analiz Tamamlandı!" -ForegroundColor Green
Write-Host "[*] Detaylı HTML Raporu Masaüstüne Kaydedildi: Silva_Ag_Guvenlik_Raporu.html" -ForegroundColor Yellow

# --- İNTERAKTİF SÜREÇ SONLANDIRMA (KILL) ÖZELLİĞİ ---
$kritikKayitlar = $report | Where-Object { $_."Risk Seviyesi" -eq "KRİTİK" -or $_."Risk Seviyesi" -eq "YÜKSEK" }

if ($kritikKayitlar) {
    Write-Host "`n[!] DİKKAT: Sistemde yüksek riskli veya kritik seviyede süreçler tespit edildi!" -ForegroundColor Red
    $secim = Read-Host "Bu şüpheli süreçlerden sonlandırmak istediğiniz PID var mı? (Sonlandırmak istiyorsanız PID yazın, geçmek için Enter'a basın)"
    
    if ($secim -match '^\d+$') {
        Stop-Process -Id $secim -Force -ErrorAction SilentlyContinue
        Write-Host "[+] $secim PID numaralı süreç başarıyla sonlandırıldı." -ForegroundColor Green
    }
}

# Grid penceresi ile görsel liste gösterimi
$report | Out-GridView -Title "Silva - Gelişmiş Ağ ve Risk Analiz Raporu"
