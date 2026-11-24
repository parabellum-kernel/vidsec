$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$VidsecRoot = Split-Path -Parent $ScriptDir

if (-not $env:VIDSEC_CALLER_PWD) {
    $env:VIDSEC_CALLER_PWD = (Get-Location).Path
}

# Load configs/.env if present
$DotEnvPath = Join-Path $VidsecRoot "configs\.env"
if (Test-Path $DotEnvPath) {
    Get-Content $DotEnvPath | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
            $parts = $line -split "=", 2
            $key = $parts[0].Trim()
            $val = $parts[1].Trim().Trim('"').Trim("'")
            [Environment]::SetEnvironmentVariable($key, $val, "Process")
        }
    }
}

if (-not $env:PARABELLUM_PLUGIN_DIR) {
    $DistLib = Join-Path $VidsecRoot "lib"
    if (Test-Path $DistLib) {
        $env:PARABELLUM_PLUGIN_DIR = $DistLib
    } else {
        $env:PARABELLUM_PLUGIN_DIR = Join-Path $VidsecRoot "zig-out\lib"
    }
}

$EngineBin = $env:PARABELLUM_ENGINE_BIN
if (-not $EngineBin) {
    $DistBin = Join-Path $VidsecRoot "bin\parabellum-engine.exe"
    if (Test-Path $DistBin) {
        $EngineBin = $DistBin
    } else {
        $EngineBin = Join-Path (Split-Path -Parent $VidsecRoot) "engine\zig-out\bin\parabellum-engine.exe"
    }
}

$Pipeline = if ($env:PIPELINE_PATH) { $env:PIPELINE_PATH } else { Join-Path $VidsecRoot "configs\pipeline.yaml" }

$Cmd = if ($args.Count -gt 0) { $args[0] } else { "tui" }
$Rest = if ($args.Count -gt 1) { $args[1..($args.Count - 1)] } else { @() }

Push-Location $VidsecRoot
try {
    if ($Cmd -in @("tui", "-t", "--tui", "serve", "-s", "--serve")) {
        $LogDir = Join-Path $VidsecRoot "data\logs"
        New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
        $Stamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $ErrLog = Join-Path $LogDir "engine_$Stamp.log"
        Write-Host "==> Starting Parabellum Engine with VidSec TUI ('$Pipeline')..."
        & $EngineBin --plugin-dir $env:PARABELLUM_PLUGIN_DIR --serve --transport vidsec_tui --pipeline $Pipeline @Rest 2>> $ErrLog
        exit $LASTEXITCODE
    } elseif ($Cmd -in @("validate", "-v", "--validate")) {
        Write-Host "==> Validating pipeline '$Pipeline'..."
        & $EngineBin --plugin-dir $env:PARABELLUM_PLUGIN_DIR validate $Pipeline @Rest
        exit $LASTEXITCODE
    } elseif ($Cmd -eq "run") {
        Write-Host "==> Running Parabellum pipeline '$Pipeline'..."
        & $EngineBin --plugin-dir $env:PARABELLUM_PLUGIN_DIR run $Pipeline @Rest
        exit $LASTEXITCODE
    } else {
        & $EngineBin --plugin-dir $env:PARABELLUM_PLUGIN_DIR run $args
        exit $LASTEXITCODE
    }
} finally {
    Pop-Location
}
