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
    [string]$RemoteSecretsPath = "/opt/nazo-oauth/secrets.json",
    [string]$RemoteConformanceUiPath = "/opt/nazo-oauth/ui",
    [string]$LocalConformanceAuthTemplate = "deploy/conformance-ui/auth/index.html.template",
    [string]$LocalConformanceConsentHtml = "deploy/conformance-ui/consent/index.html",
    [string]$HealthUrl = "https://auth.nazo.run/health",
    [string]$DiscoveryUrl = "https://auth.nazo.run/.well-known/openid-configuration",
    [string]$ExpectedIssuer = "https://auth.nazo.run",
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
$remoteAuthTemplate = "/tmp/nazo-oauth-auth-$safeTag.html.template"
$remoteConsentHtml = "/tmp/nazo-oauth-consent-$safeTag.html"
$localRemoteScript = Join-Path ([System.IO.Path]::GetTempPath()) "nazo-oauth-deploy-$safeTag.sh"

Write-Host "Deploying $image to $RemoteHost"

if (-not (Test-Path -LiteralPath $LocalConformanceAuthTemplate)) {
    throw "Missing conformance auth template: $LocalConformanceAuthTemplate"
}
if (-not (Test-Path -LiteralPath $LocalConformanceConsentHtml)) {
    throw "Missing conformance consent HTML: $LocalConformanceConsentHtml"
}

if (-not $SkipBuild) {
    Invoke-Checked docker @("build", "-f", "Containerfile", "-t", $image, ".")
}

if (Test-Path -LiteralPath $archive) {
    Remove-Item -LiteralPath $archive -Force
}
Invoke-Checked docker @("save", $image, "-o", $archive)
Invoke-Checked scp $archive "${RemoteHost}:$remoteArchive"
Invoke-Checked scp $LocalConformanceAuthTemplate "${RemoteHost}:$remoteAuthTemplate"
Invoke-Checked scp $LocalConformanceConsentHtml "${RemoteHost}:$remoteConsentHtml"

$skipMigrateValue = if ($SkipMigrate) { "1" } else { "0" }
$remoteBody = @"
set -euo pipefail

IMAGE=$(ConvertTo-ShellLiteral $image)
REMOTE_ARCHIVE=$(ConvertTo-ShellLiteral $remoteArchive)
REMOTE_SCRIPT=$(ConvertTo-ShellLiteral $remoteScript)
REMOTE_AUTH_TEMPLATE=$(ConvertTo-ShellLiteral $remoteAuthTemplate)
REMOTE_CONSENT_HTML=$(ConvertTo-ShellLiteral $remoteConsentHtml)
CONTAINER_NAME=$(ConvertTo-ShellLiteral $ContainerName)
NETWORK_NAME=$(ConvertTo-ShellLiteral $Network)
CONTAINER_IP=$(ConvertTo-ShellLiteral $IPAddress)
CONFIG_PATH=$(ConvertTo-ShellLiteral $RemoteConfigPath)
KEYS_PATH=$(ConvertTo-ShellLiteral $RemoteKeysPath)
AVATARS_PATH=$(ConvertTo-ShellLiteral $RemoteAvatarsPath)
SECRETS_PATH=$(ConvertTo-ShellLiteral $RemoteSecretsPath)
CONFORMANCE_UI_PATH=$(ConvertTo-ShellLiteral $RemoteConformanceUiPath)
SKIP_MIGRATE=$(ConvertTo-ShellLiteral $skipMigrateValue)
export REMOTE_AUTH_TEMPLATE REMOTE_CONSENT_HTML SECRETS_PATH CONFORMANCE_UI_PATH

cleanup() {
  rm -f "`$REMOTE_ARCHIVE" "`$REMOTE_SCRIPT" "`$REMOTE_AUTH_TEMPLATE" "`$REMOTE_CONSENT_HTML"
}
trap cleanup EXIT

test -f "`$CONFIG_PATH"
test -d "`$KEYS_PATH"
test -d "`$AVATARS_PATH"
test -f "`$SECRETS_PATH"

python3 - <<'PY'
import json
import os
from pathlib import Path

secrets_path = Path(os.environ["SECRETS_PATH"])
ui_path = Path(os.environ["CONFORMANCE_UI_PATH"])
auth_template_path = Path(os.environ["REMOTE_AUTH_TEMPLATE"])
consent_html_path = Path(os.environ["REMOTE_CONSENT_HTML"])

secrets = json.loads(secrets_path.read_text(encoding="utf-8"))
email = secrets.get("oidf_user_email")
password = secrets.get("oidf_user_password")
if not isinstance(email, str) or not email:
    raise SystemExit("oidf_user_email is missing from remote secrets")
if not isinstance(password, str) or not password:
    raise SystemExit("oidf_user_password is missing from remote secrets")

auth_html = auth_template_path.read_text(encoding="utf-8")
auth_html = auth_html.replace("__OIDF_USER_EMAIL_JSON__", json.dumps(email))
auth_html = auth_html.replace("__OIDF_USER_PASSWORD_JSON__", json.dumps(password))
if "__OIDF_USER_" in auth_html:
    raise SystemExit("conformance auth template placeholders were not fully rendered")

auth_dir = ui_path / "auth"
consent_dir = ui_path / "consent"
auth_dir.mkdir(parents=True, exist_ok=True)
consent_dir.mkdir(parents=True, exist_ok=True)
(auth_dir / "index.html").write_text(auth_html, encoding="utf-8")
(consent_dir / "index.html").write_text(consent_html_path.read_text(encoding="utf-8"), encoding="utf-8")
PY

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
