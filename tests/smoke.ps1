param(
    [switch]$SkipBuild
)

# Automated smoke test: PE mapping + emulator initialization end-to-end.
# Generates a minimal x64 .sys, runs KEVLAR against it, and asserts that
# DriverEntry was reached and returned STATUS_SUCCESS.

$ErrorActionPreference = "Stop"
$root = (Split-Path -Parent $PSScriptRoot)
$buildDir = Join-Path $root "builds\Release"
$exe = Join-Path $buildDir "KEVLAR.exe"
$drv = Join-Path $PSScriptRoot "test_driver.sys"
$log = Join-Path $env:TEMP "kevlar_smoke.log"

if (-not $SkipBuild) {
    & (Join-Path $root "build.ps1") Release | Out-Host
    if ($LASTEXITCODE) { throw "build failed" }
}

if (-not (Test-Path $exe)) { throw "KEVLAR.exe not found - run build.ps1 first" }

& python (Join-Path $PSScriptRoot "make_test_driver.py") $drv --verify | Out-Host
if ($LASTEXITCODE) { throw "test driver generation failed" }

Write-Host "Running KEVLAR smoke test (no-pause)..."
& $exe $drv --no-pause 2>&1 | Tee-Object -FilePath $log | Out-Null
$out = Get-Content $log -Raw

$fail = @()
if ($out -notmatch "DriverEntry completed successfully") { $fail += "DriverEntry did not complete" }
if ($out -notmatch "DriverEntry returned:") { $fail += "no DriverEntry return value logged" }
if ($out -match "DriverEntry failed or was stopped") { $fail += "DriverEntry was stopped" }

if ($fail.Count) {
    Write-Host "SMOKE FAIL:" -ForegroundColor Red
    $fail | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}

$ret = ($out -split "`n") | Where-Object { $_ -match "DriverEntry returned:" }
Write-Host "SMOKE PASS - $($ret.Trim())" -ForegroundColor Green
exit 0
