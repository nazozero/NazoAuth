param(
    [string]$RemoteHost = "nazo.run",
    [string]$ImageRepository = "localhost/nazo-oauth-server",
    [string]$ImageTag = "",
    [string]$ContainerName = "nazo-oauth-server",
    [string]$Network = "nazo_oauth_net",
    [string]$IPAddress = "10.101.0.20",
    [string]$RemoteConfigPath = "/opt/nazo-oauth/.env.yaml",
    [string]$RemoteKeysPath = "/opt/nazo-oauth/runtime/keys",
    [string]$RemoteAvatarsPath = "/opt/nazo-oauth/runtime/avatars",
    [string]$HealthUrl = "https://oauth.nazo.run/health",
    [string]$DiscoveryUrl = "https://oauth.nazo.run/.well-known/openid-configuration",
    [string]$ExpectedIssuer = "https://oauth.nazo.run",
    [switch]$SkipBuild,
    [switch]$SkipMigrate
)

$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed: $FilePath $($Arguments -join ' ')"
    }
}

function Get-CommandOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    $output = & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed: $FilePath $($Arguments -join ' ')"
    }
    return ($output | Select-Object -First 1)
}

function ConvertTo-ShellLiteral {
    param([Parameter(Mandatory = $true)][string]$Value)
    $singleQuote = [string][char]39
    $escapedQuote = $singleQuote + "\" + $singleQuote + $singleQuote
    return $singleQuote + $Value.Replace($singleQuote, $escapedQuote) + $singleQuote
}

if (-not $ImageTag) {
    $ImageTag = "main-$(Get-CommandOutput git rev-parse --short=7 HEAD)"
}

$image = "${ImageRepository}:$ImageTag"
$safeTag = $ImageTag -replace '[^A-Za-z0-9_.-]', '-'
$archive = Join-Path ([System.IO.Path]::GetTempPath()) "nazo-oauth-server-$safeTag.tar"
$remoteArchive = "/tmp/nazo-oauth-server-$safeTag.tar"
$remoteScript = "/tmp/nazo-oauth-deploy-$safeTag.sh"
$localRemoteScript = Join-Path ([System.IO.Path]::GetTempPath()) "nazo-oauth-deploy-$safeTag.sh"

Write-Host "Deploying $image to $RemoteHost"

if (-not $SkipBuild) {
    Invoke-Checked docker @("build", "-f", "Containerfile", "-t", $image, ".")
}

if (Test-Path -LiteralPath $archive) {
    Remove-Item -LiteralPath $archive -Force
}
Invoke-Checked docker @("save", $image, "-o", $archive)
Invoke-Checked scp $archive "${RemoteHost}:$remoteArchive"

$skipMigrateValue = if ($SkipMigrate) { "1" } else { "0" }
$remoteBody = @"
set -euo pipefail

IMAGE=$(ConvertTo-ShellLiteral $image)
REMOTE_ARCHIVE=$(ConvertTo-ShellLiteral $remoteArchive)
REMOTE_SCRIPT=$(ConvertTo-ShellLiteral $remoteScript)
CONTAINER_NAME=$(ConvertTo-ShellLiteral $ContainerName)
NETWORK_NAME=$(ConvertTo-ShellLiteral $Network)
CONTAINER_IP=$(ConvertTo-ShellLiteral $IPAddress)
CONFIG_PATH=$(ConvertTo-ShellLiteral $RemoteConfigPath)
KEYS_PATH=$(ConvertTo-ShellLiteral $RemoteKeysPath)
AVATARS_PATH=$(ConvertTo-ShellLiteral $RemoteAvatarsPath)
SKIP_MIGRATE=$(ConvertTo-ShellLiteral $skipMigrateValue)

cleanup() {
  rm -f "`$REMOTE_ARCHIVE" "`$REMOTE_SCRIPT"
}
trap cleanup EXIT

test -f "`$CONFIG_PATH"
test -d "`$KEYS_PATH"
test -d "`$AVATARS_PATH"

podman load -i "`$REMOTE_ARCHIVE"
podman image exists "`$IMAGE"

if [ "`$SKIP_MIGRATE" != "1" ]; then
  migrate_name="`$CONTAINER_NAME-migrate-`$(date +%s)"
  podman run --rm --name "`$migrate_name" \
    --network "`$NETWORK_NAME" \
    -v "`$CONFIG_PATH:/app/.env.yaml:ro" \
    -v "`$KEYS_PATH:/var/lib/nazo_oauth/keys:rw" \
    -v "`$AVATARS_PATH:/var/lib/nazo_oauth/avatars:rw" \
    "`$IMAGE" nazo-oauth-migrate
fi

if podman container exists "`$CONTAINER_NAME"; then
  podman rm -f "`$CONTAINER_NAME"
fi

podman run -d --name "`$CONTAINER_NAME" \
  --network "`$NETWORK_NAME" --ip "`$CONTAINER_IP" \
  -v "`$CONFIG_PATH:/app/.env.yaml:ro" \
  -v "`$KEYS_PATH:/var/lib/nazo_oauth/keys:rw" \
  -v "`$AVATARS_PATH:/var/lib/nazo_oauth/avatars:rw" \
  "`$IMAGE" nazo-oauth-server

podman inspect "`$CONTAINER_NAME" --format 'container={{.Name}} image={{.ImageName}} status={{.State.Status}}'
podman inspect "`$CONTAINER_NAME" --format '{{range `$name, `$conf := .NetworkSettings.Networks}}network={{`$name}} ip={{`$conf.IPAddress}}{{println}}{{end}}'
"@

Set-Content -LiteralPath $localRemoteScript -Value $remoteBody -Encoding UTF8
try {
    Invoke-Checked scp $localRemoteScript "${RemoteHost}:$remoteScript"
    Invoke-Checked ssh $RemoteHost @("bash", $remoteScript)
}
finally {
    Remove-Item -LiteralPath $localRemoteScript -Force -ErrorAction SilentlyContinue
}

$health = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 20
if ($health.StatusCode -ne 200) {
    throw "Health probe failed: HTTP $($health.StatusCode)"
}

$discovery = Invoke-WebRequest -Uri $DiscoveryUrl -UseBasicParsing -TimeoutSec 20
if ($discovery.StatusCode -ne 200) {
    throw "Discovery probe failed: HTTP $($discovery.StatusCode)"
}

$metadata = $discovery.Content | ConvertFrom-Json
if ($metadata.issuer -ne $ExpectedIssuer) {
    throw "Unexpected issuer in discovery document: $($metadata.issuer)"
}

Write-Host "Deployment verified: $image"
