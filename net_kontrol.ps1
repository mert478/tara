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
Write-Host "   AKILLI AG GUVENLIGI VE RISK ANALIZ ARACI      " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "[*] Ag baglantilari ve dosya yollari taraniyor..." -ForegroundColor Yellow

$connections = Get-NetTCPConnection -ErrorAction SilentlyContinue

# Guvenilir bilinen sistem surecleri listesi
$trustedProcs = @("svchost", "lsass", "csrss", "wininit", "services", "explorer", "chrome", "firefox", "msedge", "discord", "spotify", "steam", "code", "NGENUITY", "NZXT CAM", "EABackgroundService", "GameManagerService3")

$report = foreach ($conn in $connections) {
    $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
    
    $procName = if ($proc) { $proc.Name } else { "Bilinmiyor" }
    $procPath = if ($proc) { $proc.Path } else { "-" }
    
    # --- RISK ANALIZ MOTORU ---
    $riskStatus = "Normal / Guvenli"
    $riskLevel = "Dusuk"

    if (-not $proc) {
        $riskStatus = "PID Sahipsiz / Kapanmis Surec"
        $riskLevel = "Orta"
    }
    elseif ($procPath -ne "-") {
        if ($procPath -match "AppData|Temp|Public|Users\\Public|ProgramData") {
            $riskStatus = "SUPHELI DIZIN! (Kullanici alani/Temp altindan calisiyor)"
            $riskLevel = "YUKSEK"
        }
        elseif ($procName -in @("svchost", "lsass", "explorer") -and $procPath -notmatch "C:\\Windows\\System32|C:\\Windows\\") {
            $riskStatus = "SAHTE SISTEM DOSYASI OLABILIR!"
            $riskLevel = "KRITIK"
        }
        elseif ($trustedProcs -notcontains $procName -and $conn.RemoteAddress -notmatch "127\.0\.0\.1|0\.0\.0\.0|::1|^192\.168\.|^10\.") {
            $riskLevel = "Orta"
            $riskStatus = "Harici Ag Baglantisi (Bilinmeyen Program)"
        }
    }

    [PSCustomObject]@{
        "Risk Seviyesi" = $riskLevel
        "Analiz Notu"   = $riskStatus
        "Program Adi"   = $procName
        "Yerel Adres"   = "$($conn.LocalAddress):$($conn.LocalPort)"
        "Uzak Adres"    = "$($conn.RemoteAddress):$($conn.RemotePort)"
        "Durum"         = $conn.State
        "PID"           = $conn.OwningProcess
        "Dosya Yolu"    = $procPath
    }
}

# Raporu masaustune kaydet
$desktop = [Environment]::GetFolderPath("Desktop")
$htmlPath = Join-Path $desktop "Akilli_Ag_Guvenlik_Raporu.html"
$csvPath = Join-Path $desktop "Akilli_Ag_Guvenlik_Raporu.csv"

$report | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
$report | ConvertTo-Html -Title "Akilli Ag Guvenlik Raporu" | Out-File -FilePath $htmlPath -Encoding utf8

Write-Host "`n[+] Analiz Tamamlandi!" -ForegroundColor Green
Write-Host "[*] Detayli Rapor Masaustune Kaydedildi: Akilli_Ag_Guvenlik_Raporu.html" -ForegroundColor Yellow

# Grid penceresi ile goster
$report | Out-GridView -Title "Akilli Ag ve Risk Analiz Raporu"