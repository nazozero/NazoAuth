param(
    [Parameter(Mandatory = $true)]
    [string]$RemoteHost,
    [Parameter(Mandatory = $true)]
    [string]$BackendCommit,
    [Parameter(Mandatory = $true)]
    [string]$FrontendCommit,
    [string]$ImageRepository = "localhost/nazo-oauth-server",
    [string]$ImageTag = "",
    [string]$ContainerName = "nazo-oauth-server",
    [string]$Network = "nazo_oauth_net",
    [string]$NetworkSubnet = "10.101.0.0/24",
    [string]$NetworkGateway = "10.101.0.1",
    [string]$IPAddress = "10.101.0.20",
    [string]$RemoteConfigPath = "/opt/nazo-oauth/.env.yaml",
    [string]$RemoteKeysPath = "/opt/nazo-oauth/runtime/keys",
    [string]$RemoteAvatarsPath = "/opt/nazo-oauth/runtime/avatars",
    [string]$RemoteUiPath = "/opt/nazo-oauth/ui",
    [string]$RemoteDeploymentRoot = "/opt/nazo-oauth",
    [string]$LocalUiDist = "../NazoAuthWeb/dist",
    [string]$PublishPort = "",
    [string]$HealthUrl = "https://auth.nazo.run/health",
    [string]$DiscoveryUrl = "https://auth.nazo.run/.well-known/openid-configuration",
    [string]$ExpectedIssuer = "https://auth.nazo.run",
    [string]$RenderRemoteScriptPath = "",
    [switch]$SkipBuild,
    [switch]$SkipMigrate
)

$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed: $FilePath $($Arguments -join ' ')"
    }
}

function Get-CommandOutput {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )
    $output = & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed: $FilePath $($Arguments -join ' ')"
    }
    return ($output | Select-Object -First 1)
}

function ConvertTo-ShellLiteral {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    $singleQuote = [string][char]39
    $escapedQuote = $singleQuote + "\" + $singleQuote + $singleQuote
    return $singleQuote + $Value.Replace($singleQuote, $escapedQuote) + $singleQuote
}

if ($BackendCommit -notmatch '^[0-9a-f]{40}$') {
    throw "BackendCommit must be a full lowercase Git SHA"
}
if ($FrontendCommit -notmatch '^[0-9a-f]{40}$') {
    throw "FrontendCommit must be a full lowercase Git SHA"
}
if (-not $ImageTag) {
    $ImageTag = "modular-$($BackendCommit.Substring(0, 7))-web-$($FrontendCommit.Substring(0, 7))"
}
if (-not (Test-Path -LiteralPath (Join-Path $LocalUiDist "index.html"))) {
    throw "Missing frontend dist index.html: $LocalUiDist"
}

$image = "${ImageRepository}:$ImageTag"
$safeTag = $ImageTag -replace '[^A-Za-z0-9_.-]', '-'
$archive = Join-Path ([System.IO.Path]::GetTempPath()) "nazo-oauth-server-$safeTag.tar"
$uiArchive = Join-Path ([System.IO.Path]::GetTempPath()) "nazo-oauth-web-$safeTag.tar.gz"
$localRemoteScript = Join-Path ([System.IO.Path]::GetTempPath()) "nazo-oauth-deploy-$safeTag.sh"

Write-Host "Staging $image ($BackendCommit / $FrontendCommit) on $RemoteHost"

if ($RenderRemoteScriptPath) {
    $remoteTempDir = "/tmp/nazo-oauth-deploy.render"
}
else {
    if (-not $SkipBuild) {
        Invoke-Checked docker @(
            "build", "-f", "Containerfile",
            "--label", "org.opencontainers.image.revision=$BackendCommit",
            "-t", $image, "."
        )
    }
    Remove-Item -LiteralPath $archive, $uiArchive -Force -ErrorAction SilentlyContinue
    Invoke-Checked docker @("save", $image, "-o", $archive)
    Invoke-Checked tar @("-C", $LocalUiDist, "-czf", $uiArchive, ".")
    $remoteTempDir = Get-CommandOutput ssh $RemoteHost @("mktemp", "-d", "/tmp/nazo-oauth-deploy.XXXXXX")
}
$remoteArchive = "$remoteTempDir/nazo-oauth-server-$safeTag.tar"
$remoteUiArchive = "$remoteTempDir/nazo-oauth-web-$safeTag.tar.gz"
$remoteScript = "$remoteTempDir/deploy.sh"
$remoteState = "$remoteTempDir/state.env"
if (-not $RenderRemoteScriptPath) {
    Invoke-Checked scp $archive "${RemoteHost}:$remoteArchive"
    Invoke-Checked scp $uiArchive "${RemoteHost}:$remoteUiArchive"
}

$skipMigrateValue = if ($SkipMigrate) { "1" } else { "0" }
$remoteBody = @"
#!/usr/bin/env bash
set -euo pipefail

IMAGE=$(ConvertTo-ShellLiteral $image)
BACKEND_COMMIT=$(ConvertTo-ShellLiteral $BackendCommit)
FRONTEND_COMMIT=$(ConvertTo-ShellLiteral $FrontendCommit)
REMOTE_ARCHIVE=$(ConvertTo-ShellLiteral $remoteArchive)
REMOTE_UI_ARCHIVE=$(ConvertTo-ShellLiteral $remoteUiArchive)
REMOTE_SCRIPT=$(ConvertTo-ShellLiteral $remoteScript)
STATE_FILE=$(ConvertTo-ShellLiteral $remoteState)
CONTAINER_NAME=$(ConvertTo-ShellLiteral $ContainerName)
NETWORK_NAME=$(ConvertTo-ShellLiteral $Network)
NETWORK_SUBNET=$(ConvertTo-ShellLiteral $NetworkSubnet)
NETWORK_GATEWAY=$(ConvertTo-ShellLiteral $NetworkGateway)
CONTAINER_IP=$(ConvertTo-ShellLiteral $IPAddress)
CONFIG_PATH=$(ConvertTo-ShellLiteral $RemoteConfigPath)
KEYS_PATH=$(ConvertTo-ShellLiteral $RemoteKeysPath)
AVATARS_PATH=$(ConvertTo-ShellLiteral $RemoteAvatarsPath)
UI_PATH=$(ConvertTo-ShellLiteral $RemoteUiPath)
DEPLOYMENT_ROOT=$(ConvertTo-ShellLiteral $RemoteDeploymentRoot)
PUBLISH_PORT=$(ConvertTo-ShellLiteral $PublishPort)
EXPECTED_ISSUER=$(ConvertTo-ShellLiteral $ExpectedIssuer)
SKIP_MIGRATE=$(ConvertTo-ShellLiteral $skipMigrateValue)

UI_RELEASES="`$DEPLOYMENT_ROOT/ui-releases"
DEPLOYMENTS="`$DEPLOYMENT_ROOT/deployments"
UI_RELEASE="`$UI_RELEASES/`$FRONTEND_COMMIT"
RECORD="`$DEPLOYMENTS/`$BACKEND_COMMIT.json"

run_server() {
  local selected_image="`$1"
  local publish_args=()
  if [ -n "`$PUBLISH_PORT" ]; then publish_args=(-p "`$PUBLISH_PORT"); fi
  podman run -d --name "`$CONTAINER_NAME" \
    --network "`$NETWORK_NAME" --ip "`$CONTAINER_IP" \
    "`${publish_args[@]}" \
    -v "`$CONFIG_PATH:/app/.env.yaml:ro" \
    -v "`$KEYS_PATH:/var/lib/nazo_oauth/keys:rw" \
    -v "`$AVATARS_PATH:/var/lib/nazo_oauth/avatars:rw" \
    "`$selected_image" nazo-oauth-server >/dev/null
}

write_record() {
  local status="`$1"
  python3 - "`$RECORD" "`$status" "`$BACKEND_COMMIT" "`$FRONTEND_COMMIT" \
    "`$IMAGE" "`${previous_image:-}" "`${previous_container_id:-}" \
    "`${previous_ui_target:-}" "`${candidate_container_id:-}" <<'PY'
import json, pathlib, sys, time
path = pathlib.Path(sys.argv[1])
payload = {
    "status": sys.argv[2],
    "backend_commit": sys.argv[3],
    "frontend_commit": sys.argv[4],
    "candidate_image": sys.argv[5],
    "previous_image": sys.argv[6],
    "previous_container_id": sys.argv[7],
    "previous_ui_target": sys.argv[8],
    "candidate_container_id": sys.argv[9],
    "recorded_at_unix": int(time.time()),
}
path.parent.mkdir(parents=True, exist_ok=True)
temporary = path.with_suffix(".json.tmp")
temporary.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
temporary.replace(path)
PY
}

save_state() {
  cat >"`$STATE_FILE" <<EOF
previous_image='`${previous_image//\'/\'\\\'\'}'
previous_container_id='`${previous_container_id//\'/\'\\\'\'}'
previous_ui_kind='`${previous_ui_kind//\'/\'\\\'\'}'
previous_ui_target='`${previous_ui_target//\'/\'\\\'\'}'
legacy_ui_release='`${legacy_ui_release//\'/\'\\\'\'}'
candidate_container_id='`${candidate_container_id//\'/\'\\\'\'}'
EOF
}

load_state() {
  test -f "`$STATE_FILE"
  # Values are generated locally from inspected paths/image identifiers.
  source "`$STATE_FILE"
}

rollback() {
  set +e
  if [ -f "`$STATE_FILE" ]; then load_state; fi
  if podman container exists "`$CONTAINER_NAME"; then podman rm -f "`$CONTAINER_NAME" >/dev/null; fi
  if [ -n "`${previous_image:-}" ]; then run_server "`$previous_image"; fi
  if [ -L "`$UI_PATH" ]; then rm -f "`$UI_PATH"; fi
  if [ "`${previous_ui_kind:-missing}" = "symlink" ] && [ -n "`${previous_ui_target:-}" ]; then
    ln -s "`$previous_ui_target" "`$UI_PATH"
  elif [ "`${previous_ui_kind:-missing}" = "directory" ] && [ -n "`${legacy_ui_release:-}" ] && [ -d "`$legacy_ui_release" ]; then
    mv -T "`$legacy_ui_release" "`$UI_PATH"
  fi
  write_record "rolled-back" 2>/dev/null || true
  curl -fsS --max-time 20 "http://`$CONTAINER_IP:8000/health" >/dev/null 2>&1 || true
  set -e
}

cleanup() {
  rm -f "`$REMOTE_ARCHIVE" "`$REMOTE_UI_ARCHIVE" "`$REMOTE_SCRIPT" "`$STATE_FILE"
  rmdir "`$(dirname "`$REMOTE_SCRIPT")" 2>/dev/null || true
}

deploy() {
  test -f "`$CONFIG_PATH"
  test -d "`$KEYS_PATH"
  test -d "`$AVATARS_PATH"
  test "`$(df -Pk "`$DEPLOYMENT_ROOT" | awk 'NR==2 {print `$4}')" -gt 1048576
  podman network exists "`$NETWORK_NAME"
  podman run --rm --network "`$NETWORK_NAME" docker.io/library/postgres:18 \
    pg_isready -h 10.101.0.10 -p 5432 >/dev/null
  podman exec nazo-oauth-valkey valkey-cli ping | grep -Fx PONG >/dev/null

  mkdir -p "`$UI_RELEASES" "`$DEPLOYMENTS"
  rm -rf "`$UI_RELEASE.tmp"
  mkdir -p "`$UI_RELEASE.tmp"
  tar -xzf "`$REMOTE_UI_ARCHIVE" -C "`$UI_RELEASE.tmp"
  test -s "`$UI_RELEASE.tmp/index.html"
  if [ -e "`$UI_RELEASE" ]; then rm -rf "`$UI_RELEASE.tmp"; else mv "`$UI_RELEASE.tmp" "`$UI_RELEASE"; fi

  previous_image=""
  previous_container_id=""
  if podman container exists "`$CONTAINER_NAME"; then
    previous_image="`$(podman inspect "`$CONTAINER_NAME" --format '{{.ImageName}}')"
    previous_container_id="`$(podman inspect "`$CONTAINER_NAME" --format '{{.Id}}')"
  fi
  previous_ui_kind="missing"
  previous_ui_target=""
  legacy_ui_release=""
  if [ -L "`$UI_PATH" ]; then
    previous_ui_kind="symlink"
    previous_ui_target="`$(readlink "`$UI_PATH")"
  elif [ -d "`$UI_PATH" ]; then
    previous_ui_kind="directory"
    previous_ui_target="`$UI_PATH"
    legacy_ui_release="`$UI_RELEASES/legacy-`$(date +%s)"
  fi
  candidate_container_id=""
  save_state
  write_record "preflight"

  trap 'rollback' ERR
  podman load -i "`$REMOTE_ARCHIVE" >/dev/null
  podman image exists "`$IMAGE"
  actual_revision="`$(podman image inspect "`$IMAGE" --format '{{index .Labels "org.opencontainers.image.revision"}}')"
  test "`$actual_revision" = "`$BACKEND_COMMIT"

  if [ "`$SKIP_MIGRATE" != "1" ]; then
    podman run --rm --name "`$CONTAINER_NAME-migrate-`$(date +%s)" \
      --network "`$NETWORK_NAME" \
      -v "`$CONFIG_PATH:/app/.env.yaml:ro" \
      -v "`$KEYS_PATH:/var/lib/nazo_oauth/keys:rw" \
      -v "`$AVATARS_PATH:/var/lib/nazo_oauth/avatars:rw" \
      "`$IMAGE" nazo-oauth-migrate
  fi

  if podman container exists "`$CONTAINER_NAME"; then podman rm -f "`$CONTAINER_NAME" >/dev/null; fi
  run_server "`$IMAGE"
  candidate_container_id="`$(podman inspect "`$CONTAINER_NAME" --format '{{.Id}}')"
  save_state
  actual_ip="`$(podman inspect "`$CONTAINER_NAME" --format '{{range `$name, `$conf := .NetworkSettings.Networks}}{{println `$conf.IPAddress}}{{end}}' | awk 'NF {print; exit}')"
  test "`$actual_ip" = "`$CONTAINER_IP"
  curl -fsS --max-time 20 "http://`$CONTAINER_IP:8000/health" >/dev/null
  discovery="`$(curl -fsS --max-time 20 "http://`$CONTAINER_IP:8000/.well-known/openid-configuration")"
  python3 -c 'import json,sys; assert json.load(sys.stdin)["issuer"] == sys.argv[1]' "`$EXPECTED_ISSUER" <<<"`$discovery"

  if [ "`$previous_ui_kind" = "directory" ]; then mv -T "`$UI_PATH" "`$legacy_ui_release"; fi
  temporary_link="`$UI_PATH.next-`$BACKEND_COMMIT"
  rm -f "`$temporary_link"
  ln -s "`$UI_RELEASE" "`$temporary_link"
  mv -T "`$temporary_link" "`$UI_PATH"
  write_record "candidate-verified"
  trap - ERR
}

commit_deployment() {
  load_state
  write_record "deployment-success"
  ln -sfn "`$RECORD" "`$DEPLOYMENTS/current.json"
  cleanup
}

case "`${1:-deploy}" in
  deploy) deploy ;;
  rollback) load_state; rollback; cleanup ;;
  commit) load_state; commit_deployment ;;
  *) echo "unknown deployment action" >&2; exit 2 ;;
esac
"@

if ($RenderRemoteScriptPath) {
    Set-Content -LiteralPath $RenderRemoteScriptPath -Value $remoteBody -Encoding UTF8
    return
}
Set-Content -LiteralPath $localRemoteScript -Value $remoteBody -Encoding UTF8
$remoteStarted = $false
try {
    Invoke-Checked scp $localRemoteScript "${RemoteHost}:$remoteScript"
    $remoteStarted = $true
    Invoke-Checked ssh $RemoteHost @("bash", $remoteScript, "deploy")

    $health = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 20
    if ($health.StatusCode -ne 200) { throw "Health probe failed: HTTP $($health.StatusCode)" }
    $discovery = Invoke-WebRequest -Uri $DiscoveryUrl -UseBasicParsing -TimeoutSec 20
    if ($discovery.StatusCode -ne 200) { throw "Discovery probe failed: HTTP $($discovery.StatusCode)" }
    $metadata = $discovery.Content | ConvertFrom-Json
    if ($metadata.issuer -ne $ExpectedIssuer) {
        throw "Unexpected issuer in discovery document: $($metadata.issuer)"
    }

    Invoke-Checked ssh $RemoteHost @("bash", $remoteScript, "commit")
    $remoteStarted = $false
    Write-Host "Deployment verified: $image deployment-success"
}
catch {
    if ($remoteStarted) {
        & ssh $RemoteHost bash $remoteScript rollback
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Automatic rollback command failed; inspect $RemoteHost immediately"
        }
    }
    throw
}
finally {
    Remove-Item -LiteralPath $localRemoteScript, $uiArchive, $archive -Force -ErrorAction SilentlyContinue
}
