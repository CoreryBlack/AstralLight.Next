[CmdletBinding()]
param(
    [switch]$Offline
)

# Requires PowerShell 7+ (pwsh) and cargo on PATH.
# Default mode may access crates.io when dependencies are not cached locally.
# Use -Offline to pass --offline; it fails instead of using the network when the
# local Cargo registry/cache is incomplete.
# Integration tests marked #[ignore] are intentionally not run here. They require
# external MySQL, Redis, RabbitMQ, and migration setup.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$sourceRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$manifestPath = Join-Path $sourceRoot 'Cargo.toml'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "Rust workspace manifest was not found: $manifestPath"
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'astral-light-rust-excluded-' + [System.Guid]::NewGuid().ToString('N')
)
$exitCode = 1
$locationPushed = $false
$hadCargoTargetDirectory = Test-Path Env:CARGO_TARGET_DIR
$originalCargoTargetDirectory = $env:CARGO_TARGET_DIR

function Copy-SourceTree {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    foreach ($item in Get-ChildItem -LiteralPath $Source -Force) {
        if ($item.PSIsContainer -and $item.Name -in @('.git', 'target')) {
            continue
        }

        $destinationPath = Join-Path $Destination $item.Name
        if ($item.PSIsContainer) {
            Copy-SourceTree -Source $item.FullName -Destination $destinationPath
        } else {
            Copy-Item -LiteralPath $item.FullName -Destination $destinationPath -Force
        }
    }
}

function Add-ExcludedServiceMembers {
    param(
        [Parameter(Mandatory = $true)][string]$Manifest
    )

    $membersMatch = [regex]::Match(
        $Manifest,
        '(?ms)^(?<prefix>members\s*=\s*\[)(?<body>.*?)(?<closing>\r?\n\s*\])'
    )
    if (-not $membersMatch.Success) {
        throw 'The temporary Cargo.toml has no recognizable workspace members array.'
    }

    $body = $membersMatch.Groups['body'].Value
    $lineEnding = if ($Manifest.Contains("`r`n")) { "`r`n" } else { "`n" }
    foreach ($member in @('astral-chat', 'astral-learn')) {
        if ($body -notmatch ('(?m)^\s*"' + [regex]::Escape($member) + '"\s*,?\s*$')) {
            $body += $lineEnding + ('    "' + $member + '",')
        }
    }

    return $Manifest.Substring(0, $membersMatch.Index) +
        $membersMatch.Groups['prefix'].Value +
        $body +
        $membersMatch.Groups['closing'].Value +
        $Manifest.Substring($membersMatch.Index + $membersMatch.Length)
}

try {
    Write-Host "[verify] Copying Rust workspace to temporary directory: $tempRoot"
    Copy-SourceTree -Source $sourceRoot -Destination $tempRoot

    $temporaryManifestPath = Join-Path $tempRoot 'Cargo.toml'
    $temporaryManifest = Get-Content -LiteralPath $temporaryManifestPath -Raw
    $modifiedManifest = Add-ExcludedServiceMembers -Manifest $temporaryManifest
    [System.IO.File]::WriteAllText(
        $temporaryManifestPath,
        $modifiedManifest,
        [System.Text.UTF8Encoding]::new($false)
    )

    $env:CARGO_TARGET_DIR = Join-Path $tempRoot 'target'
    $cargoArguments = @()
    if ($Offline) {
        $cargoArguments += '--offline'
        Write-Host '[verify] Offline mode enabled; Cargo will not access the network.'
    } else {
        Write-Host '[verify] Network access is allowed if Cargo dependencies are not cached.'
    }

    Push-Location -LiteralPath $tempRoot
    $locationPushed = $true
    Write-Host '[cargo] cargo check -p astral-chat -p astral-learn'
    & cargo check @cargoArguments -p astral-chat -p astral-learn
    $checkExitCode = [int]$LASTEXITCODE
    if ($checkExitCode -ne 0) {
        $exitCode = $checkExitCode
        throw "cargo check failed with exit code $checkExitCode."
    }

    Write-Host '[cargo] cargo test -p astral-chat -p astral-learn'
    Write-Host '[verify] Tests marked #[ignore] are intentionally skipped; see the script header.'
    & cargo test @cargoArguments -p astral-chat -p astral-learn
    $exitCode = [int]$LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "cargo test failed with exit code $exitCode."
    }

    Write-Host '[done] Excluded service verification passed.'
} catch {
    Write-Error $_
} finally {
    if ($locationPushed) {
        Pop-Location
    }

    if ($hadCargoTargetDirectory) {
        $env:CARGO_TARGET_DIR = $originalCargoTargetDirectory
    } else {
        Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue
    }

    if (Test-Path -LiteralPath $tempRoot) {
        try {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction Stop
            Write-Host '[cleanup] Temporary workspace removed.'
        } catch {
            Write-Error "Failed to remove temporary workspace '$tempRoot': $_"
            if ($exitCode -eq 0) {
                $exitCode = 1
            }
        }
    }
}

exit $exitCode
