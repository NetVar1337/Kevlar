param(
    [string]$Pdb = "",   # default: builds\Release\pdb_cache\ntkrnlmp.pdb
    [string]$Output = "" # default: generated\kernel_layout.h
)

# Build tools\pdb_layout\pdb_layout.cpp with the DIA SDK and run it against a
# kernel PDB to regenerate structure-layout defines. Keeps the harness's
# ntoskrnl_struct.h untouched; output lands in generated\kernel_layout.h.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "Visual Studio Installer not found" }

$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) { throw "VS C++ build tools not found" }
$vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
$diaInc = Join-Path $vsPath "DIA SDK\include"
$diaLib = Join-Path $vsPath "DIA SDK\lib\amd64"
$diaBin = Join-Path $vsPath "DIA SDK\bin\amd64"
if (-not (Test-Path (Join-Path $diaInc "dia2.h"))) { throw "DIA SDK not found under $vsPath" }
if (-not (Test-Path (Join-Path $diaBin "msdia140.dll"))) { throw "msdia140.dll not found under $diaBin" }

if (-not $Pdb) {
    # symbol-server cache layout: <name>.pdb/<GUID>/<name>.pdb
    $pdbDir = Join-Path $root "builds\Release\pdb_cache\ntkrnlmp.pdb"
    $Pdb = Get-ChildItem -Path $pdbDir -Recurse -Filter "*.pdb" -File | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $Output) { $Output = Join-Path $root "generated\kernel_layout.h" }
if (-not $Pdb -or -not (Test-Path $Pdb)) { throw "PDB not found" }

$src = Join-Path $PSScriptRoot "pdb_layout\pdb_layout.cpp"
$exe = Join-Path $env:TEMP "pdb_layout.exe"
New-Item -ItemType Directory -Force (Split-Path -Parent $Output) | Out-Null

$cmd = "call `"$vcvars`" && cl /nologo /EHsc /std:c++20 /I `"$diaInc`" `"$src`" /Fe:`"$exe`" /link /LIBPATH:`"$diaLib`" diaguids.lib ole32.lib oleaut32.lib"
Write-Host "Compiling pdb_layout..."
cmd /c $cmd
if ($LASTEXITCODE) { throw "compile failed ($LASTEXITCODE)" }

Write-Host "Generating layout from $Pdb -> $Output"
$env:DIA_SDK_BIN = $diaBin
& $exe $Pdb $Output
if ($LASTEXITCODE) { throw "pdb_layout failed ($LASTEXITCODE)" }
Write-Host "Done: $Output"
