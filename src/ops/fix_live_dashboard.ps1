param(
    [string]$VmHost = "4.213.0.215",
    [string]$VmUser = "azureuser",
    [string]$HostKey = "SHA256:WLRjGMg5a0tsNgH0LcBDv1e7bsEcKz/4/uOOoL5+P6M",
    [int]$GrafanaPort = 3300,
    [int]$ApiPort = 8800
)

$ErrorActionPreference = "Stop"

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$plink = "C:\Program Files\PuTTY\plink.exe"

if (-not (Test-Path $plink)) {
    throw "PuTTY plink.exe not found at $plink"
}

$securePassword = Read-Host "Enter Azure VM password for $VmUser@$VmHost" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
$plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
$sudoPasswordB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($plainPassword))

function Invoke-Remote {
    param([string]$Command)
    & $plink -ssh -batch -hostkey $HostKey -pw $plainPassword "$VmUser@$VmHost" $Command
}

function Copy-TextToRemote {
    param(
        [string]$LocalPath,
        [string]$RemotePath
    )
    Get-Content -Raw -Path $LocalPath | & $plink -ssh -batch -hostkey $HostKey -pw $plainPassword "$VmUser@$VmHost" "cat > '$RemotePath'"
}

function Invoke-BashRemote {
    param([string]$Script)
    $linuxScript = $Script -replace "`r`n", "`n"
    $linuxScript | & $plink -ssh -batch -hostkey $HostKey -pw $plainPassword "$VmUser@$VmHost" "bash -s"
}

Write-Host "[1/5] Uploading realtime ETL, dashboard stabilizer, and MySQL performance indexes..."
Copy-TextToRemote `
    -LocalPath (Join-Path $projectRoot "src\etl\ingest.py") `
    -RemotePath "/tmp/realtime_ingest.py"

Copy-TextToRemote `
    -LocalPath (Join-Path $projectRoot "src\grafana\stabilize_dashboard.py") `
    -RemotePath "/tmp/stabilize_dashboard.py"

Copy-TextToRemote `
    -LocalPath (Join-Path $projectRoot "src\db\performance_indexes.sql") `
    -RemotePath "/tmp/cowrie_performance_indexes.sql"

$remoteRepair = @"
set -e
PROJECT_DIR="/home/azureuser/cowrie_ml_pipeline"
if [ ! -d "`$PROJECT_DIR" ]; then
  PROJECT_DIR="/home/azureuser/cowrie_ml_pipeline"
fi
cd "`$PROJECT_DIR"
cp /tmp/realtime_ingest.py cowrie_prod/etl/realtime_ingest.py
mkdir -p cowrie_prod/grafana
cp /tmp/stabilize_dashboard.py cowrie_prod/grafana/stabilize_dashboard.py
python3 -m py_compile cowrie_prod/etl/realtime_ingest.py cowrie_prod/grafana/stabilize_dashboard.py
mysql -u cowrie_user -pcowrie_pass cowrie_prod < /tmp/cowrie_performance_indexes.sql
SUDO_PASSWORD=`$(printf '%s' '$sudoPasswordB64' | base64 -d)
printf '%s\n' "`$SUDO_PASSWORD" | sudo -S python3 cowrie_prod/grafana/stabilize_dashboard.py
printf '%s\n' "`$SUDO_PASSWORD" | sudo -S systemctl restart cowrie-ml-etl cowrie-ml-api grafana-server
sleep 5
systemctl is-active cowrie cowrie-ml-etl cowrie-ml-api grafana-server
curl -s --max-time 10 http://127.0.0.1:8000/ || true
curl -s --max-time 10 http://127.0.0.1:3000/api/health || true
"@

Write-Host "[2/5] Applying repair on Azure VM..."
Invoke-BashRemote $remoteRepair

Write-Host "[3/5] Restarting local Grafana/FastAPI tunnel..."
Get-CimInstance Win32_Process |
    Where-Object {
        $_.Name -eq "plink.exe" -and
        $_.CommandLine -match "$GrafanaPort`:127\.0\.0\.1`:3000" -and
        $_.CommandLine -match "$ApiPort`:127\.0\.0\.1`:8000"
    } |
    ForEach-Object {
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }

Start-Process -WindowStyle Hidden -FilePath $plink -ArgumentList @(
    "-ssh",
    "-batch",
    "-hostkey",
    $HostKey,
    "-pw",
    $plainPassword,
    "-N",
    "-L",
    "$GrafanaPort`:127.0.0.1:3000",
    "-L",
    "$ApiPort`:127.0.0.1:8000",
    "$VmUser@$VmHost"
)

Start-Sleep -Seconds 5

Write-Host "[4/5] Testing local tunnel health..."
$grafanaHealth = curl.exe --max-time 20 -s "http://127.0.0.1:$GrafanaPort/api/health"
$apiHealth = curl.exe --max-time 20 -s "http://127.0.0.1:$ApiPort/"

Write-Host "Grafana: $grafanaHealth"
Write-Host "FastAPI:  $apiHealth"

Write-Host "[5/5] Open this dashboard:"
Write-Host "http://127.0.0.1:$GrafanaPort/d/cowrie-ml-soc/cowrie-ml-soc-dashboard-all-attacks?orgId=1&from=now-1h&to=now&timezone=browser&refresh=10s"

$plainPassword = $null
$sudoPasswordB64 = $null
