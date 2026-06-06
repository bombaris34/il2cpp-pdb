<#
.SYNOPSIS
  Build the il2cpp_pdbgen tool so Il2CppDumper can auto-generate a PDB after dumping
  an x64 PE (GameAssembly.dll).

.DESCRIPTION
  - Builds il2cpp_pdbgen (Rust, release) and copies the resulting exe next to the
    Il2CppDumper build output so the dumper finds it automatically.
  - If Rust/cargo is missing, pass -InstallRust to install it via winget or rustup.

.EXAMPLE
  .\setup.ps1                # build (requires cargo on PATH)
  .\setup.ps1 -InstallRust   # install Rust first if needed, then build
#>
param(
    [switch]$InstallRust
)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

function Have($name) { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }

# 1. Ensure cargo.
if (-not (Have 'cargo')) {
    # rustup may be installed but not on this session's PATH.
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    if (Test-Path (Join-Path $cargoBin 'cargo.exe')) {
        $env:Path = "$cargoBin;$env:Path"
    }
}
if (-not (Have 'cargo')) {
    if (-not $InstallRust) {
        Write-Host "Rust/cargo not found." -ForegroundColor Yellow
        Write-Host "Re-run with -InstallRust, or install from https://rustup.rs and re-run setup."
        exit 1
    }
    Write-Host "Installing Rust..." -ForegroundColor Cyan
    if (Have 'winget') {
        winget install --id Rustlang.Rustup -e --accept-source-agreements --accept-package-agreements
    } else {
        $tmp = Join-Path $env:TEMP 'rustup-init.exe'
        Invoke-WebRequest -Uri 'https://win.rustup.rs/x86_64' -OutFile $tmp
        & $tmp -y --default-toolchain stable --profile minimal
    }
    $env:Path = "$(Join-Path $env:USERPROFILE '.cargo\bin');$env:Path"
    if (-not (Have 'cargo')) {
        Write-Host "cargo still not found after install. Open a new terminal and re-run setup.ps1." -ForegroundColor Yellow
        exit 1
    }
}

# 2. Build the tool.
Write-Host "Building il2cpp_pdbgen (release)..." -ForegroundColor Cyan
Push-Location (Join-Path $root 'il2cpp_pdbgen')
try {
    # cargo writes progress/warnings to stderr; don't let that abort the script.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    cargo build --release 2>&1 | ForEach-Object { Write-Host $_ }
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prev
    if ($code -ne 0) { throw "cargo build failed (exit $code)" }
} finally {
    Pop-Location
}
$exe = Join-Path $root 'il2cpp_pdbgen\target\release\il2cpp_pdbgen.exe'
if (-not (Test-Path $exe)) { throw "build succeeded but $exe is missing" }

# 3. Copy next to the Il2CppDumper build output(s) so the dumper finds it.
$copied = $false
foreach ($cfg in @('Release', 'Debug')) {
    $d = Join-Path $root "Il2CppDumper\bin\$cfg\net8.0"
    if (Test-Path $d) {
        Copy-Item $exe $d -Force
        Write-Host "Copied il2cpp_pdbgen.exe -> $d" -ForegroundColor Green
        $copied = $true
    }
}
if (-not $copied) {
    Write-Host "Built $exe" -ForegroundColor Green
    Write-Host "(No Il2CppDumper build output found yet; build Il2CppDumper, then re-run setup.ps1 to copy the tool next to it.)" -ForegroundColor Yellow
}
Write-Host "Done. Il2CppDumper will now auto-generate a PDB for x64 PE targets (set GeneratePdb=false in config.json to disable)." -ForegroundColor Cyan
