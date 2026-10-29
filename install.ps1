[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$GuardianExe,

    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    [string]$TokenPath,

    [string]$PublicKeyPath
)

$ErrorActionPreference = 'Stop'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this installer from an elevated PowerShell session.'
    }
}

function Assert-File([string]$Path, [string]$Description) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Description was not found: $Path"
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

try {
    Assert-Administrator
    $GuardianExe = Assert-File $GuardianExe 'Guardian executable'
    $ConfigPath = Assert-File $ConfigPath 'Guardian configuration'

    $buildInfo = & $GuardianExe version
    if ($LASTEXITCODE -ne 0) {
        throw "Could not read Guardian build information (exit code $LASTEXITCODE)."
    }
    Write-Host "Guardian package: $buildInfo"

    $validation = & $GuardianExe validate-config -config $ConfigPath
    if ($LASTEXITCODE -ne 0) {
        throw "Guardian rejected the supplied configuration (exit code $LASTEXITCODE)."
    }
    Write-Host $validation

    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    if ($config.listen_addr -notmatch ':(53)$') {
        throw 'System-wide installation requires listen_addr to use port 53.'
    }
    if ($config.remote.enabled -and -not $TokenPath) {
        throw 'The config enables remote updates; provide -TokenPath for the read-only GitHub token.'
    }
    if ($config.remote.require_signature -and -not $PublicKeyPath) {
        throw 'The config requires signatures; provide -PublicKeyPath for the Ed25519 public key.'
    }
    if ($TokenPath) {
        $TokenPath = Assert-File $TokenPath 'GitHub token file'
    }
    if ($PublicKeyPath) {
        $PublicKeyPath = Assert-File $PublicKeyPath 'Config signature public key'
    }

    $dataDir = Join-Path $env:ProgramData 'Guardian'
    $installedConfig = Join-Path $dataDir 'config.json'
    if (Test-Path -LiteralPath $installedConfig -PathType Leaf) {
        Write-Host 'Existing installation detected. Its protected config and parent password will be preserved during upgrade.'
    } else {
        Write-Host 'A new installation will prompt you to create a parent password; it is never included in the package.'
    }
    New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
    & icacls.exe $dataDir '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not restrict permissions on $dataDir (icacls exit code $LASTEXITCODE)."
    }

    if ($TokenPath) {
        Copy-Item -LiteralPath $TokenPath -Destination (Join-Path $dataDir 'github-token.txt') -Force
    }
    if ($PublicKeyPath) {
        Copy-Item -LiteralPath $PublicKeyPath -Destination (Join-Path $dataDir 'config-public.key') -Force
    }

    & $GuardianExe install -config $ConfigPath
    if ($LASTEXITCODE -ne 0) {
        throw "Guardian service installation failed with exit code $LASTEXITCODE."
    }
    Write-Host 'Guardian installed. Run guardian.exe status to inspect service and enforcement state.'
}
catch {
    Write-Error $_
    exit 1
}
