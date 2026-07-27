# Збирає реліз greatie під Windows для x86_64 та arm64.
# MSVC-тулчейн підтримує обидві архітектури, але ARM64 потребує окремого
# компонента "MSVC v143 - VS2022 C++ ARM64 build tools" у Visual Studio —
# якщо його немає, збірка цієї цілі просто пропускається з попередженням.

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$BinName = "greatie"
$DistDir = "dist"
$Targets = @("x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc")

if (Test-Path $DistDir) {
    Remove-Item -Recurse -Force $DistDir
}
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

foreach ($target in $Targets) {
    Write-Host "==> Очищення попередньої збірки для $target"
    cargo clean --release --target $target 2>$null | Out-Null

    Write-Host "==> Збірка для $target"
    rustup target add $target 2>$null | Out-Null

    cargo build --release --target $target
    if ($LASTEXITCODE -eq 0) {
        $arch = $target.Split("-")[0]
        $outPath = Join-Path $DistDir "$BinName-windows-$arch.exe"
        # Вкладені (не багатосегментні) виклики Join-Path — сумісно і з
        # Windows PowerShell 5.1, і з PowerShell 7+.
        $releaseDir = Join-Path (Join-Path "target" $target) "release"
        Copy-Item (Join-Path $releaseDir "$BinName.exe") $outPath -Force
        Write-Host "    -> $outPath"
    } else {
        Write-Warning "Збірка для $target не вдалася — пропускаю (можливо, немає ARM64 build tools)."
    }
}

Write-Host "Готово. Бінарники у $DistDir\"
