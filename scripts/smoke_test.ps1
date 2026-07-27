# Sanity/smoke-тести вже зібраного greatie.exe перед деплоєм артифакту
# (Windows). Дублює перевірки scripts/smoke_test.sh, але без зовнішніх
# утиліт типу dumpbin: тип PE (x64/ARM64) читається напряму з байтів
# заголовка, а перевірка залежностей — непряма: якщо якийсь DLL відсутній,
# запуск процесу впаде з помилкою завантаження, яку ми тут ловимо.
#
# Використання: smoke_test.ps1 -BinPath <шлях-до-.exe> [-LogPath <файл>]
param(
    [Parameter(Mandatory = $true)][string]$BinPath,
    [string]$LogPath = "smoke-test.log"
)

$ErrorActionPreference = "Continue"
Set-Content -Path $LogPath -Value ""
$script:Failed = $false

function Log([string]$Message) {
    Write-Host $Message
    Add-Content -Path $LogPath -Value $Message
}

function Step([string]$Name, [ScriptBlock]$Action) {
    Log "==> $Name"
    try {
        $output = & $Action 2>&1
        foreach ($line in $output) { Add-Content -Path $LogPath -Value $line }
        if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) {
            Log "    FAIL (exit $LASTEXITCODE)"
            $script:Failed = $true
        } else {
            Log "    OK"
        }
    } catch {
        Log "    FAIL (exception: $_)"
        $script:Failed = $true
    }
}

Log "=== Smoke test: $BinPath ==="

if (-not (Test-Path $BinPath)) {
    Log "!! Бінарник не знайдено: $BinPath"
    exit 1
}

Log "==> PE-заголовок — перевірка архітектури"
$bytes = [System.IO.File]::ReadAllBytes($BinPath)
$peOffset = [System.BitConverter]::ToInt32($bytes, 0x3C)
$machine = [System.BitConverter]::ToUInt16($bytes, $peOffset + 4)
$machineName = switch ($machine) {
    0x8664 { "x64 (AMD64)" }
    0xAA64 { "ARM64" }
    0x014c { "x86" }
    default { "невідомо (0x{0:X4})" -f $machine }
}
Log "    Machine: $machineName"

$tmp = Join-Path $env:TEMP ("greatie-smoke-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
$sample = Join-Path $tmp "sample.bin"
$pngHeader = [byte[]](0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)
$zipHeader = [byte[]](0x50, 0x4B, 0x03, 0x04)
$bytesOut = $pngHeader + (New-Object byte[] 4096) + $zipHeader + (New-Object byte[] 2048)
[System.IO.File]::WriteAllBytes($sample, $bytesOut)

Step "--version" { & $BinPath --version }
Step "--help" { & $BinPath --help }
Step "--formats" { & $BinPath --formats }
Step "scan --format json" { & $BinPath scan $sample --format json }
Step "scan --format table" { & $BinPath scan $sample --format table }
Step "entropy --format json" { & $BinPath entropy $sample --format json }

Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue

if ($script:Failed) {
    Log "=== Підсумок: FAIL ==="
    exit 1
} else {
    Log "=== Підсумок: PASS ==="
    exit 0
}
