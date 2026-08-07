param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"

if (-not (Test-Path $vswhere)) {
    throw "Visual Studio Installer was not found. Install Visual Studio 2022 Build Tools with the C++ workload."
}

$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) {
    throw "Visual Studio 2022 C++ build tools were not found."
}

$vcpkg = Join-Path $vsPath "VC\vcpkg\vcpkg.exe"
$msbuild = Join-Path $vsPath "MSBuild\Current\Bin\amd64\MSBuild.exe"

Push-Location $root
try {
    & $vcpkg install --triplet x64-windows-static
    if ($LASTEXITCODE) { throw "vcpkg failed with exit code $LASTEXITCODE" }

    & $msbuild "KEVLAR.sln" -m -restore "/p:Configuration=$Configuration" "/p:Platform=x64" "/p:VcpkgEnableManifest=true" "/p:VcpkgManifestRoot=$root" "/p:VcpkgTriplet=x64-windows-static"
    if ($LASTEXITCODE) { throw "MSBuild failed with exit code $LASTEXITCODE" }
} finally {
    Pop-Location
}

Write-Host "Built: $root\builds\$Configuration\KEVLAR.exe"
