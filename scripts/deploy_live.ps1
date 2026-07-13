param(
    [Parameter(Mandatory = $true)]
    [string]$RemoteHost,
    [Parameter(Mandatory = $true)]
    [string]$BackendCommit,
    [Parameter(Mandatory = $true)]
    [string]$FrontendCommit,
    [string]$LocalFrontendWorktree = "",
    [string]$LocalBackendWorktree = ".",
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
    [string]$LocalUiDist = "",
    [string]$PublishPort = "",
    [string]$HealthUrl = "https://auth.nazo.run/health",
    [string]$DiscoveryUrl = "https://auth.nazo.run/.well-known/openid-configuration",
    [string]$ExpectedIssuer = "https://auth.nazo.run",
    [ValidateRange(1, 3600)]
    [int]$VerificationLeaseSeconds = 120,
    [string]$RenderRemoteScriptPath = "",
    [string]$RenderRemoteTempDir = "/tmp/nazo-oauth-deploy.render",
    [switch]$SkipBuild,
    [switch]$SkipFrontendBuild,
    [switch]$SkipMigrate
)

$ErrorActionPreference = "Stop"
$ExpectedBackendRemote = "https://github.com/nazozero/NazoAuth"
$ExpectedBackendBranch = "codex/modular-workspace-architecture"
$ExpectedFrontendRemote = "https://github.com/nazozero/NazoAuthWeb"
$ExpectedFrontendBranch = "codex/modular-workspace-architecture"

if ($RemoteHost.StartsWith('-') -or
    $RemoteHost -notmatch '^(?:[A-Za-z0-9_][A-Za-z0-9._-]*@)?[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$') {
    throw "RemoteHost must be a safe SSH host alias, hostname, or user@host"
}

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

function Assert-CleanGitCommit {
    param(
        [Parameter(Mandatory = $true)][string]$Worktree,
        [Parameter(Mandatory = $true)][string]$ExpectedCommit,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $root = Get-CommandOutput git @("-C", $Worktree, "rev-parse", "--show-toplevel")
    $actualCommit = Get-CommandOutput git @("-C", $root, "rev-parse", "HEAD")
    if ($actualCommit -cne $ExpectedCommit) {
        throw "$Label HEAD $actualCommit does not match requested commit $ExpectedCommit"
    }
    $status = & git -C $root status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to inspect $Label worktree: $root"
    }
    if ($status) {
        throw "$Label worktree must be clean (tracked and untracked build inputs): $root"
    }
    return [System.IO.Path]::GetFullPath($root)
}

function ConvertTo-GitHubRepositoryIdentity {
    param([Parameter(Mandatory = $true)][string]$Remote)
    $trimmed = $Remote.Trim()
    $patterns = @(
        '^(?:https?://)github\.com/(?<owner>[^/]+)/(?<repository>[^/]+?)(?:\.git)?/?$',
        '^git@github\.com:(?<owner>[^/]+)/(?<repository>[^/]+?)(?:\.git)?/?$',
        '^ssh://git@github\.com/(?<owner>[^/]+)/(?<repository>[^/]+?)(?:\.git)?/?$'
    )
    foreach ($pattern in $patterns) {
        if ($trimmed -match $pattern) {
            return "$($Matches.owner.ToLowerInvariant())/$($Matches.repository.ToLowerInvariant())"
        }
    }
    throw "Unsupported GitHub remote URL: $Remote"
}

function Assert-GitOrigin {
    param(
        [Parameter(Mandatory = $true)][string]$Worktree,
        [Parameter(Mandatory = $true)][string]$ExpectedRemote,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $actual = Get-CommandOutput git @("-C", $Worktree, "remote", "get-url", "origin")
    try {
        $normalizedActual = ConvertTo-GitHubRepositoryIdentity -Remote $actual
    }
    catch {
        throw "$Label origin $actual is not a supported GitHub SSH or HTTPS remote"
    }
    $normalizedExpected = ConvertTo-GitHubRepositoryIdentity -Remote $ExpectedRemote
    if ($normalizedActual -cne $normalizedExpected) {
        throw "$Label origin $actual does not identify expected repository $normalizedExpected"
    }
}

function Assert-SynchronizedGitUpstream {
    param(
        [Parameter(Mandatory = $true)][string]$Worktree,
        [Parameter(Mandatory = $true)][string]$ExpectedBranch,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $upstream = & git -C $Worktree rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $upstream) {
        throw "$Label branch $ExpectedBranch must have an upstream"
    }
    $upstream = $upstream | Select-Object -First 1
    $expectedUpstream = "origin/$ExpectedBranch"
    if ($upstream -cne $expectedUpstream) {
        throw "$Label upstream $upstream does not match expected upstream $expectedUpstream"
    }
    $divergence = Get-CommandOutput git @(
        "-C", $Worktree, "rev-list", "--left-right", "--count", "HEAD...@{upstream}"
    )
    if ($divergence -notmatch '^\s*(?<ahead>\d+)\s+(?<behind>\d+)\s*$') {
        throw "Unable to parse $Label upstream divergence: $divergence"
    }
    if ([int]$Matches.ahead -ne 0 -or [int]$Matches.behind -ne 0) {
        throw "$Label branch $ExpectedBranch is not synchronized with $upstream (ahead $($Matches.ahead), behind $($Matches.behind))"
    }
}

function Assert-FrontendWorktree {
    param(
        [Parameter(Mandatory = $true)][string]$Worktree,
        [Parameter(Mandatory = $true)][string]$ExpectedCommit
    )
    $root = Assert-CleanGitCommit -Worktree $Worktree -ExpectedCommit $ExpectedCommit -Label "Frontend"
    $branch = Get-CommandOutput git @("-C", $root, "branch", "--show-current")
    if ($branch -cne $ExpectedFrontendBranch) {
        throw "Frontend branch $branch does not match expected branch $ExpectedFrontendBranch"
    }
    Assert-GitOrigin -Worktree $root -ExpectedRemote $ExpectedFrontendRemote -Label "Frontend"
    Assert-SynchronizedGitUpstream -Worktree $root -ExpectedBranch $ExpectedFrontendBranch -Label "Frontend"
    return $root
}

function Find-FrontendWorktree {
    param(
        [Parameter(Mandatory = $true)][string]$BackendWorktree,
        [Parameter(Mandatory = $true)][string]$ExpectedCommit
    )
    $commonGitDir = Get-CommandOutput git @(
        "-C", $BackendWorktree, "rev-parse", "--path-format=absolute", "--git-common-dir"
    )
    $backendRepository = Split-Path -Parent $commonGitDir
    $siblingRoot = Split-Path -Parent $backendRepository
    $directories = @(
        Get-ChildItem -LiteralPath $siblingRoot -Directory -Force |
            Where-Object { $_.Name -eq "NazoAuthWeb" -or $_.Name -like "NazoAuthWeb-*" } |
            Sort-Object FullName
    )
    $qualified = [System.Collections.Generic.List[string]]::new()
    $rejected = [System.Collections.Generic.List[string]]::new()
    foreach ($directory in $directories) {
        try {
            $qualified.Add((Assert-FrontendWorktree -Worktree $directory.FullName -ExpectedCommit $ExpectedCommit))
        }
        catch {
            $rejected.Add("$($directory.FullName): $($_.Exception.Message)")
        }
    }
    if ($qualified.Count -eq 1) {
        return $qualified[0]
    }
    if ($qualified.Count -gt 1) {
        throw "Frontend worktree discovery is ambiguous; qualified candidates: $($qualified -join ', '). Pass LocalFrontendWorktree explicitly."
    }
    $details = if ($rejected.Count -gt 0) { " Rejected candidates: $($rejected -join '; ')" } else { "" }
    throw "Unable to discover a unique synchronized sibling NazoAuthWeb worktree under $siblingRoot.$details Pass LocalFrontendWorktree explicitly."
}

function Export-GitCommit {
    param(
        [Parameter(Mandatory = $true)][string]$Worktree,
        [Parameter(Mandatory = $true)][string]$Commit,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $identifier = [guid]::NewGuid().ToString("N")
    $archivePath = Join-Path ([System.IO.Path]::GetTempPath()) "nazo-$Label-$identifier.tar"
    $exportPath = Join-Path ([System.IO.Path]::GetTempPath()) "nazo-$Label-$identifier"
    New-Item -ItemType Directory -Path $exportPath | Out-Null
    try {
        Invoke-Checked git @("-C", $Worktree, "archive", "--format=tar", "--output=$archivePath", $Commit)
        Invoke-Checked tar @("-xf", $archivePath, "-C", $exportPath)
        return $exportPath
    }
    catch {
        Remove-Item -LiteralPath $exportPath -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
    finally {
        Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
    }
}

function Get-FrontendArtifactDigest {
    param([Parameter(Mandatory = $true)][string]$DistPath)
    $root = [System.IO.Path]::GetFullPath($DistPath)
    $reparsePoint = Get-ChildItem -LiteralPath $root -Recurse -Force |
        Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 } |
        Select-Object -First 1
    if ($reparsePoint) {
        throw "Frontend dist must not contain symlinks or reparse points: $($reparsePoint.FullName)"
    }
    $entries = Get-ChildItem -LiteralPath $root -File -Recurse -Force |
        Where-Object { $_.Name -ne ".nazo-build.json" } |
        Sort-Object FullName |
        ForEach-Object {
            $relative = [System.IO.Path]::GetRelativePath($root, $_.FullName).Replace('\', '/')
            $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            "$relative`t$hash`n"
        }
    $canonical = [string]::Concat([string[]]$entries)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($canonical)
    return [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

function Write-FrontendBuildManifest {
    param(
        [Parameter(Mandatory = $true)][string]$DistPath,
        [Parameter(Mandatory = $true)][string]$SourceCommit
    )
    $manifestPath = Join-Path $DistPath ".nazo-build.json"
    $manifest = [ordered]@{
        schema = 1
        source_commit = $SourceCommit
        artifact_sha256 = Get-FrontendArtifactDigest -DistPath $DistPath
    }
    $manifest | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8
}

if ($BackendCommit -notmatch '^[0-9a-f]{40}$') {
    throw "BackendCommit must be a full lowercase Git SHA"
}
if ($FrontendCommit -notmatch '^[0-9a-f]{40}$') {
    throw "FrontendCommit must be a full lowercase Git SHA"
}
$LocalBackendWorktree = Assert-CleanGitCommit -Worktree $LocalBackendWorktree -ExpectedCommit $BackendCommit -Label "Backend"
$backendBranch = Get-CommandOutput git @("-C", $LocalBackendWorktree, "branch", "--show-current")
if ($backendBranch -cne $ExpectedBackendBranch) {
    throw "Backend branch $backendBranch does not match expected branch $ExpectedBackendBranch"
}
Assert-GitOrigin -Worktree $LocalBackendWorktree -ExpectedRemote $ExpectedBackendRemote -Label "Backend"
if (-not $LocalFrontendWorktree) {
    $LocalFrontendWorktree = Find-FrontendWorktree `
        -BackendWorktree $LocalBackendWorktree `
        -ExpectedCommit $FrontendCommit
}
else {
    $LocalFrontendWorktree = Assert-FrontendWorktree `
        -Worktree $LocalFrontendWorktree `
        -ExpectedCommit $FrontendCommit
}
if (-not $LocalUiDist) {
    $LocalUiDist = Join-Path $LocalFrontendWorktree "dist"
}
$LocalUiDist = [System.IO.Path]::GetFullPath($LocalUiDist)
$frontendRootWithSeparator = $LocalFrontendWorktree.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
if (-not $LocalUiDist.StartsWith($frontendRootWithSeparator, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "LocalUiDist must be inside LocalFrontendWorktree"
}
if (-not $RenderRemoteScriptPath -and $SkipBuild) {
    throw "SkipBuild is only allowed when rendering the remote script for tests"
}
if (-not $RenderRemoteScriptPath -and $SkipFrontendBuild) {
    throw "SkipFrontendBuild is only allowed when rendering the remote script for tests"
}
if (-not $ImageTag) {
    $ImageTag = "modular-$($BackendCommit.Substring(0, 7))-web-$($FrontendCommit.Substring(0, 7))"
}
if (-not $SkipFrontendBuild) {
    $frontendBuildContext = Export-GitCommit -Worktree $LocalFrontendWorktree -Commit $FrontendCommit -Label "frontend-source"
    try {
        if (-not (Test-Path -LiteralPath (Join-Path $frontendBuildContext "package-lock.json") -PathType Leaf)) {
            throw "Frontend deployment build requires package-lock.json"
        }
        Invoke-Checked npm @("--prefix", $frontendBuildContext, "ci")
        Invoke-Checked npm @("--prefix", $frontendBuildContext, "run", "build")
        $builtUiDist = Join-Path $frontendBuildContext "dist"
        if (-not (Test-Path -LiteralPath (Join-Path $builtUiDist "index.html") -PathType Leaf)) {
            throw "Frontend build did not produce dist/index.html"
        }
        Remove-Item -LiteralPath $LocalUiDist -Recurse -Force -ErrorAction SilentlyContinue
        Copy-Item -LiteralPath $builtUiDist -Destination $LocalUiDist -Recurse
    }
    finally {
        Remove-Item -LiteralPath $frontendBuildContext -Recurse -Force -ErrorAction SilentlyContinue
    }
    $LocalFrontendWorktree = Assert-FrontendWorktree `
        -Worktree $LocalFrontendWorktree `
        -ExpectedCommit $FrontendCommit
}
if (-not (Test-Path -LiteralPath (Join-Path $LocalUiDist "index.html") -PathType Leaf)) {
    throw "Missing frontend dist index.html: $LocalUiDist"
}
Write-FrontendBuildManifest -DistPath $LocalUiDist -SourceCommit $FrontendCommit
$frontendArtifactDigest = Get-FrontendArtifactDigest -DistPath $LocalUiDist

$image = "${ImageRepository}:$ImageTag"
$safeTag = $ImageTag -replace '[^A-Za-z0-9_.-]', '-'
$archive = Join-Path ([System.IO.Path]::GetTempPath()) "nazo-oauth-server-$safeTag.tar"
$uiArchive = Join-Path ([System.IO.Path]::GetTempPath()) "nazo-oauth-web-$safeTag.tar.gz"
$localRemoteScript = Join-Path ([System.IO.Path]::GetTempPath()) "nazo-oauth-deploy-$safeTag.sh"

Write-Host "Staging $image ($BackendCommit / $FrontendCommit) on $RemoteHost"

$expectedImageId = "sha256:" + ("0" * 64)
if ($RenderRemoteScriptPath) {
    $remoteTempDir = $RenderRemoteTempDir
}
else {
    $backendBuildContext = Export-GitCommit -Worktree $LocalBackendWorktree -Commit $BackendCommit -Label "backend-source"
    try {
        Invoke-Checked docker @(
            "build", "-f", (Join-Path $backendBuildContext "Containerfile"),
            "--label", "org.opencontainers.image.revision=$BackendCommit",
            "-t", $image, $backendBuildContext
        )
    }
    finally {
        Remove-Item -LiteralPath $backendBuildContext -Recurse -Force -ErrorAction SilentlyContinue
    }
    $LocalBackendWorktree = Assert-CleanGitCommit -Worktree $LocalBackendWorktree -ExpectedCommit $BackendCommit -Label "Backend after build"
    $expectedImageId = Get-CommandOutput docker @("image", "inspect", $image, "--format", "{{.Id}}")
    if ($expectedImageId -notmatch '^sha256:[0-9a-f]{64}$') {
        throw "Docker returned an invalid immutable image ID: $expectedImageId"
    }
    Remove-Item -LiteralPath $archive, $uiArchive -Force -ErrorAction SilentlyContinue
    Invoke-Checked docker @("save", $image, "-o", $archive)
    Invoke-Checked tar @("-C", $LocalUiDist, "-czf", $uiArchive, ".")
    $remoteTempDir = Get-CommandOutput ssh $RemoteHost @("mktemp", "-d", "/tmp/nazo-oauth-deploy.XXXXXX")
}
$remoteArchive = "$remoteTempDir/nazo-oauth-server-$safeTag.tar"
$remoteUiArchive = "$remoteTempDir/nazo-oauth-web-$safeTag.tar.gz"
$remoteScript = "$remoteTempDir/deploy.sh"
$remoteState = "$remoteTempDir/state.json"
if (-not $RenderRemoteScriptPath) {
    Invoke-Checked scp $archive "${RemoteHost}:$remoteArchive"
    Invoke-Checked scp $uiArchive "${RemoteHost}:$remoteUiArchive"
}

$skipMigrateValue = if ($SkipMigrate) { "1" } else { "0" }
$deploymentId = [guid]::NewGuid().ToString("N")
$remoteBody = @"
#!/usr/bin/env bash
set -euo pipefail
umask 077

IMAGE=$(ConvertTo-ShellLiteral $image)
BACKEND_COMMIT=$(ConvertTo-ShellLiteral $BackendCommit)
FRONTEND_COMMIT=$(ConvertTo-ShellLiteral $FrontendCommit)
FRONTEND_ARTIFACT_SHA256=$(ConvertTo-ShellLiteral $frontendArtifactDigest)
DEPLOYMENT_ID=$(ConvertTo-ShellLiteral $deploymentId)
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
EXPECTED_IMAGE_ID=$(ConvertTo-ShellLiteral $expectedImageId)
SKIP_MIGRATE=$(ConvertTo-ShellLiteral $skipMigrateValue)
VERIFICATION_LEASE_SECONDS=$(ConvertTo-ShellLiteral $VerificationLeaseSeconds)

UI_RELEASES="`$DEPLOYMENT_ROOT/ui-releases"
DEPLOYMENTS="`$DEPLOYMENT_ROOT/deployments"
UI_RELEASE="`$UI_RELEASES/`$FRONTEND_COMMIT"
RECORD="`$DEPLOYMENTS/`$BACKEND_COMMIT-`$FRONTEND_COMMIT-`$DEPLOYMENT_ID.json"
CURRENT_LINK_TEMP="`$DEPLOYMENTS/.current-`$DEPLOYMENT_ID"
ACTIVE_DEPLOYMENT="`$DEPLOYMENTS/active-deployment"
LEASE_PENDING="`$STATE_FILE.lease-pending"
LEASE_COMMITTED="`$STATE_FILE.lease-committed"
LEASE_ROLLBACK="`$STATE_FILE.lease-rollback"
LEASE_LOCK="`$DEPLOYMENTS/lease.lock"
WATCHDOG_PID_FILE="`$STATE_FILE.watchdog-pid"

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

fsync_parent() {
  python3 - "`$1" <<'PY'
import os, pathlib, sys
if os.name == "nt":
    raise SystemExit(0)
parent = pathlib.Path(sys.argv[1]).parent
descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

write_record() {
  local status="`$1"
  python3 - "`$RECORD" "`$status" "`$BACKEND_COMMIT" "`$FRONTEND_COMMIT" \
    "`$DEPLOYMENT_ID" "`$IMAGE" "`$EXPECTED_IMAGE_ID" "`$FRONTEND_ARTIFACT_SHA256" \
    "`${previous_image_id:-}" "`${previous_image_name:-}" \
    "`${previous_container_id:-}" "`${previous_ui_target:-}" "`${candidate_container_id:-}" <<'PY'
import json, os, pathlib, sys, time
path = pathlib.Path(sys.argv[1])
payload = {
    "status": sys.argv[2],
    "backend_commit": sys.argv[3],
    "frontend_commit": sys.argv[4],
    "deployment_id": sys.argv[5],
    "candidate_image": sys.argv[6],
    "candidate_image_id": sys.argv[7],
    "frontend_artifact_sha256": sys.argv[8],
    "previous_image_id": sys.argv[9],
    "previous_image_name": sys.argv[10],
    "previous_container_id": sys.argv[11],
    "previous_ui_target": sys.argv[12],
    "candidate_container_id": sys.argv[13],
    "recorded_at_unix": int(time.time()),
}
path.parent.mkdir(parents=True, exist_ok=True)
temporary = path.with_suffix(".json.tmp")
with temporary.open("w", encoding="utf-8") as handle:
    handle.write(json.dumps(payload, sort_keys=True) + "\n")
    handle.flush()
    os.fsync(handle.fileno())
temporary.replace(path)
if os.name != "nt":
    descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
PY
}

save_state() {
  local state_dir state_temp
  state_dir="`$(dirname "`$STATE_FILE")"
  state_temp="`$(mktemp "`$state_dir/.state.XXXXXX")"
  chmod 0600 "`$state_temp"
  if ! python3 - "`$state_temp" "`$DEPLOYMENT_ID" \
    "`$previous_image_id" "`$previous_image_name" "`$previous_container_id" \
    "`$previous_ui_kind" "`$previous_ui_target" "`$legacy_ui_release" \
    "`$candidate_container_id" "`$previous_current_target" \
    "`$candidate_started" "`$ui_switched" <<'PY'
import json, os, sys
keys = (
    "deployment_id", "previous_image_id", "previous_image_name",
    "previous_container_id", "previous_ui_kind", "previous_ui_target",
    "legacy_ui_release", "candidate_container_id", "previous_current_target",
    "candidate_started", "ui_switched",
)
payload = dict(zip(keys, sys.argv[2:], strict=True))
payload["schema"] = 1
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(payload, handle, sort_keys=True)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
PY
  then
    rm -f "`$state_temp"
    return 1
  fi
  validate_state_file "`$state_temp" >/dev/null || { rm -f "`$state_temp"; return 1; }
  mv -f "`$state_temp" "`$STATE_FILE"
  fsync_parent "`$STATE_FILE"
}

validate_state_file() {
  python3 - "`$1" "`$DEPLOYMENT_ID" <<'PY'
import json, pathlib, shlex, sys
path = pathlib.Path(sys.argv[1])
try:
    payload = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"invalid deployment state: {error}")
keys = {
    "schema", "deployment_id", "previous_image_id", "previous_image_name",
    "previous_container_id", "previous_ui_kind", "previous_ui_target",
    "legacy_ui_release", "candidate_container_id", "previous_current_target",
    "candidate_started", "ui_switched",
}
if set(payload) != keys or payload.get("schema") != 1:
    raise SystemExit("invalid deployment state schema")
if payload.get("deployment_id") != sys.argv[2]:
    raise SystemExit("deployment state owner mismatch")
for key in keys - {"schema"}:
    if not isinstance(payload[key], str) or "\0" in payload[key] or "\n" in payload[key]:
        raise SystemExit(f"invalid deployment state field: {key}")
if payload["previous_ui_kind"] not in {"missing", "symlink", "directory"}:
    raise SystemExit("invalid previous_ui_kind")
if payload["candidate_started"] not in {"0", "1"} or payload["ui_switched"] not in {"0", "1"}:
    raise SystemExit("invalid deployment state flags")
for key in sorted(keys - {"schema", "deployment_id"}):
    print(f"{key}={shlex.quote(payload[key])}")
PY
}

load_state() {
  test -f "`$STATE_FILE"
  local assignments
  assignments="`$(validate_state_file "`$STATE_FILE")" || return 1
  eval "`$assignments"
}

rollback() {
  load_state || { write_record "rollback-failed" || true; return 1; }
  local image_failed=0 ui_failed=0 pointer_failed=0 restored_image
  if [ "`$candidate_started" = "1" ]; then
    if podman container exists "`$CONTAINER_NAME" && ! podman rm -f "`$CONTAINER_NAME" >/dev/null; then image_failed=1; fi
    if [ -n "`$previous_image_id" ]; then
      if ! podman image exists "`$previous_image_id"; then
        image_failed=1
      elif ! run_server "`$previous_image_id"; then
        image_failed=1
      fi
    fi
  fi
  if [ "`$ui_switched" = "1" ]; then
    if [ "`$previous_ui_kind" = "symlink" ]; then
      if [ -L "`$UI_PATH" ] && [ "`$(readlink "`$UI_PATH")" = "`$previous_ui_target" ]; then
        :
      elif { [ -L "`$UI_PATH" ] || [ -e "`$UI_PATH" ]; } && ! rm -rf "`$UI_PATH"; then
        ui_failed=1
      elif [ -n "`$previous_ui_target" ]; then
        ln -s "`$previous_ui_target" "`$UI_PATH" || ui_failed=1
      else
        ui_failed=1
      fi
    elif [ "`$previous_ui_kind" = "directory" ]; then
      if [ -n "`$legacy_ui_release" ] && [ -d "`$legacy_ui_release" ]; then
        if { [ -L "`$UI_PATH" ] || [ -e "`$UI_PATH" ]; } && ! rm -rf "`$UI_PATH"; then ui_failed=1; fi
        if [ "`$ui_failed" = "0" ]; then mv -T "`$legacy_ui_release" "`$UI_PATH" || ui_failed=1; fi
      elif [ -d "`$UI_PATH" ] && [ ! -L "`$UI_PATH" ]; then
        : # The old directory was never moved; leave it intact.
      else
        ui_failed=1
      fi
    elif { [ -L "`$UI_PATH" ] || [ -e "`$UI_PATH" ]; } && ! rm -rf "`$UI_PATH"; then
      ui_failed=1
    fi
  fi
  if [ -L "`$DEPLOYMENTS/current.json" ] && [ "`$(readlink "`$DEPLOYMENTS/current.json")" = "`$RECORD" ]; then
    if ! rm -f "`$DEPLOYMENTS/current.json"; then
      pointer_failed=1
    elif [ -n "`$previous_current_target" ]; then
      rm -f "`$CURRENT_LINK_TEMP"
      if ln -s "`$previous_current_target" "`$CURRENT_LINK_TEMP" &&
        mv -T "`$CURRENT_LINK_TEMP" "`$DEPLOYMENTS/current.json" &&
        fsync_parent "`$DEPLOYMENTS/current.json"; then
        :
      else
        pointer_failed=1
        rm -f "`$CURRENT_LINK_TEMP" || true
      fi
    elif ! fsync_parent "`$DEPLOYMENTS/current.json"; then
      pointer_failed=1
    fi
  fi
  if [ -n "`$previous_image_id" ]; then
    podman container exists "`$CONTAINER_NAME" || image_failed=1
    restored_image="`$(podman inspect "`$CONTAINER_NAME" --format '{{.Image}}' 2>/dev/null)" || image_failed=1
    [ "`$restored_image" = "`$previous_image_id" ] || image_failed=1
    curl -fsS --max-time 20 "http://`$CONTAINER_IP:8000/health" >/dev/null || image_failed=1
  elif podman container exists "`$CONTAINER_NAME"; then
    image_failed=1
  fi
  if [ "`$previous_ui_kind" = "symlink" ]; then
    [ -L "`$UI_PATH" ] && [ "`$(readlink "`$UI_PATH")" = "`$previous_ui_target" ] || ui_failed=1
  elif [ "`$previous_ui_kind" = "directory" ]; then
    [ -d "`$UI_PATH" ] && [ ! -L "`$UI_PATH" ] || ui_failed=1
  else
    [ ! -e "`$UI_PATH" ] && [ ! -L "`$UI_PATH" ] || ui_failed=1
  fi
  if [ -n "`$previous_current_target" ]; then
    [ -L "`$DEPLOYMENTS/current.json" ] &&
      [ "`$(readlink "`$DEPLOYMENTS/current.json")" = "`$previous_current_target" ] || pointer_failed=1
  else
    [ ! -e "`$DEPLOYMENTS/current.json" ] && [ ! -L "`$DEPLOYMENTS/current.json" ] || pointer_failed=1
  fi
  if [ "`$image_failed" != "0" ] || [ "`$ui_failed" != "0" ] || [ "`$pointer_failed" != "0" ]; then
    write_record "rollback-failed" || true
    return 1
  fi
  write_record "rolled-back"
}

cleanup() {
  rm -f "`$REMOTE_ARCHIVE" "`$REMOTE_UI_ARCHIVE" "`$REMOTE_SCRIPT" "`$STATE_FILE" \
    "`$WATCHDOG_PID_FILE" "`$LEASE_PENDING" "`$LEASE_COMMITTED" "`$LEASE_ROLLBACK" \
    "`$CURRENT_LINK_TEMP"
  if [ -f "`$ACTIVE_DEPLOYMENT/owner" ] && [ "`$(cat "`$ACTIVE_DEPLOYMENT/owner")" = "`$DEPLOYMENT_ID" ]; then
    rm -rf "`$ACTIVE_DEPLOYMENT"
  fi
  rmdir "`$(dirname "`$REMOTE_SCRIPT")" 2>/dev/null || true
}

stop_watchdog() {
  if [ -f "`$WATCHDOG_PID_FILE" ]; then
    watchdog_pid="`$(cat "`$WATCHDOG_PID_FILE")"
    if [[ "`$watchdog_pid" =~ ^[0-9]+`$ ]]; then
      kill "`$watchdog_pid" 2>/dev/null || true
    fi
  fi
}

start_verification_lease() {
  local watchdog_pid
  : >"`$LEASE_PENDING"
  nohup bash -c 'sleep "`$1"; exec bash "`$2" expire' _ \
    "`$VERIFICATION_LEASE_SECONDS" "`$REMOTE_SCRIPT" </dev/null >/dev/null 2>&1 &
  watchdog_pid="`$!"
  printf '%s\n' "`$watchdog_pid" >"`$WATCHDOG_PID_FILE"
  kill -0 "`$watchdog_pid"
}

rollback_transaction() {
  trap - ERR
  if [ ! -f "`$STATE_FILE" ]; then return 0; fi
  exec 9>"`$LEASE_LOCK"
  flock -x 9
  if [ ! -f "`$STATE_FILE" ]; then flock -u 9; return 0; fi
  if [ -f "`$LEASE_COMMITTED" ]; then
    echo "Deployment is already committed; refusing rollback" >&2
    return 1
  fi
  if [ -f "`$LEASE_PENDING" ]; then mv "`$LEASE_PENDING" "`$LEASE_ROLLBACK"; fi
  if rollback; then
    stop_watchdog
    flock -u 9
    cleanup
    return 0
  fi
  flock -u 9
  echo "Rollback failed; deployment evidence was preserved at `$STATE_FILE and `$RECORD" >&2
  return 1
}

assert_pending_lease() {
  test -f "`$LEASE_PENDING"
  test -f "`$ACTIVE_DEPLOYMENT/owner"
  test "`$(cat "`$ACTIVE_DEPLOYMENT/owner")" = "`$DEPLOYMENT_ID"
}

rollback_after_deploy_error() {
  trap - ERR
  flock -u 8 2>/dev/null || true
  rollback_transaction
}

deploy() {
  test -f "`$CONFIG_PATH"
  test -d "`$KEYS_PATH"
  test -d "`$AVATARS_PATH"
  test "`$(df -Pk "`$DEPLOYMENT_ROOT" | awk 'NR==2 {print `$4}')" -gt 1048576
  command -v flock >/dev/null
  podman network exists "`$NETWORK_NAME"
  network_inspect="`$(podman network inspect "`$NETWORK_NAME")"
  if ! python3 - "`$NETWORK_SUBNET" "`$NETWORK_GATEWAY" "`$network_inspect" <<'PY'; then
import json, sys
document = json.loads(sys.argv[3])
if not isinstance(document, list) or len(document) != 1 or not isinstance(document[0], dict):
    raise SystemExit(1)
subnets = document[0].get("subnets")
if not isinstance(subnets, list) or len(subnets) != 1 or not isinstance(subnets[0], dict):
    raise SystemExit(1)
entry = subnets[0]
if not isinstance(entry.get("subnet"), str) or not isinstance(entry.get("gateway"), str):
    raise SystemExit(1)
if entry["subnet"] != sys.argv[1] or entry["gateway"] != sys.argv[2]:
    raise SystemExit(1)
if document[0].get("ipv6_enabled", False) is not False:
    raise SystemExit(1)
PY
    echo "Existing Podman network `$NETWORK_NAME has unexpected subnet or gateway" >&2
    return 1
  fi
  podman run --rm --network "`$NETWORK_NAME" docker.io/library/postgres:18 \
    pg_isready -h 10.101.0.10 -p 5432 >/dev/null
  podman exec nazo-oauth-valkey valkey-cli ping | grep -Fx PONG >/dev/null

  mkdir -p "`$UI_RELEASES" "`$DEPLOYMENTS"
  if ! mkdir "`$ACTIVE_DEPLOYMENT" 2>/dev/null; then
    echo "Another deployment transaction is active" >&2
    return 1
  fi
  printf '%s\n' "`$DEPLOYMENT_ID" >"`$ACTIVE_DEPLOYMENT/owner"
  trap 'cleanup' ERR
  previous_image_id=""
  previous_image_name=""
  previous_container_id=""
  if podman container exists "`$CONTAINER_NAME"; then
    previous_image_id="`$(podman inspect "`$CONTAINER_NAME" --format '{{.Image}}')"
    previous_image_name="`$(podman inspect "`$CONTAINER_NAME" --format '{{.ImageName}}')"
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
  candidate_started="0"
  ui_switched="0"
  previous_current_target=""
  if [ -L "`$DEPLOYMENTS/current.json" ]; then
    previous_current_target="`$(readlink "`$DEPLOYMENTS/current.json")"
  fi
  save_state
  write_record "preflight"
  trap 'rollback_transaction' ERR
  start_verification_lease
  exec 8>"`$LEASE_LOCK"
  flock -x 8
  trap 'rollback_after_deploy_error' ERR
  assert_pending_lease

  rm -rf "`$UI_RELEASE.tmp"
  mkdir -p "`$UI_RELEASE.tmp"
  tar -xzf "`$REMOTE_UI_ARCHIVE" -C "`$UI_RELEASE.tmp"
  test -s "`$UI_RELEASE.tmp/index.html"
  if [ -e "`$UI_RELEASE" ]; then
    diff -qr "`$UI_RELEASE" "`$UI_RELEASE.tmp" >/dev/null
    rm -rf "`$UI_RELEASE.tmp"
  else
    mv "`$UI_RELEASE.tmp" "`$UI_RELEASE"
  fi
  assert_pending_lease
  podman load -i "`$REMOTE_ARCHIVE" >/dev/null
  podman image exists "`$IMAGE"
  actual_image_id="`$(podman image inspect "`$IMAGE" --format '{{.Id}}')"
  test "`$actual_image_id" = "`$EXPECTED_IMAGE_ID"
  actual_revision="`$(podman image inspect "`$IMAGE" --format '{{index .Labels "org.opencontainers.image.revision"}}')"
  test "`$actual_revision" = "`$BACKEND_COMMIT"
  if [ -n "`$previous_image_id" ]; then podman image exists "`$previous_image_id"; fi

  if [ "`$SKIP_MIGRATE" != "1" ]; then
    podman run --rm --name "`$CONTAINER_NAME-migrate-`$(date +%s)" \
      --network "`$NETWORK_NAME" \
      -v "`$CONFIG_PATH:/app/.env.yaml:ro" \
      -v "`$KEYS_PATH:/var/lib/nazo_oauth/keys:rw" \
      -v "`$AVATARS_PATH:/var/lib/nazo_oauth/avatars:rw" \
      "`$IMAGE" nazo-oauth-migrate
  fi
  assert_pending_lease

  candidate_started="1"
  save_state
  if podman container exists "`$CONTAINER_NAME"; then podman rm -f "`$CONTAINER_NAME" >/dev/null; fi
  run_server "`$IMAGE"
  candidate_container_id="`$(podman inspect "`$CONTAINER_NAME" --format '{{.Id}}')"
  save_state
  actual_ip="`$(podman inspect "`$CONTAINER_NAME" --format '{{range `$name, `$conf := .NetworkSettings.Networks}}{{println `$conf.IPAddress}}{{end}}' | awk 'NF {print; exit}')"
  test "`$actual_ip" = "`$CONTAINER_IP"
  curl -fsS --max-time 20 "http://`$CONTAINER_IP:8000/health" >/dev/null
  discovery="`$(curl -fsS --max-time 20 "http://`$CONTAINER_IP:8000/.well-known/openid-configuration")"
  python3 -c 'import json,sys; assert json.load(sys.stdin)["issuer"] == sys.argv[1]' "`$EXPECTED_ISSUER" <<<"`$discovery"
  assert_pending_lease

  ui_switched="1"
  save_state
  if [ "`$previous_ui_kind" = "directory" ]; then mv -T "`$UI_PATH" "`$legacy_ui_release"; fi
  temporary_link="`$UI_PATH.next-`$BACKEND_COMMIT"
  rm -f "`$temporary_link"
  ln -s "`$UI_RELEASE" "`$temporary_link"
  mv -T "`$temporary_link" "`$UI_PATH"
  write_record "candidate-verified"
  flock -u 8
  trap - ERR
}

commit_deployment() {
  load_state
  exec 9>"`$LEASE_LOCK"
  flock -x 9
  test -f "`$LEASE_PENDING"
  write_record "deployment-success"
  rm -f "`$CURRENT_LINK_TEMP"
  ln -s "`$RECORD" "`$CURRENT_LINK_TEMP"
  mv -T "`$CURRENT_LINK_TEMP" "`$DEPLOYMENTS/current.json"
  fsync_parent "`$DEPLOYMENTS/current.json"
  mv "`$LEASE_PENDING" "`$LEASE_COMMITTED"
  stop_watchdog
  flock -u 9
  cleanup
}

expire_lease() {
  if [ ! -f "`$STATE_FILE" ]; then return 0; fi
  exec 9>"`$LEASE_LOCK"
  flock -x 9
  if [ ! -f "`$LEASE_PENDING" ]; then return 0; fi
  mv "`$LEASE_PENDING" "`$LEASE_ROLLBACK"
  if rollback; then
    flock -u 9
    cleanup
    return 0
  fi
  flock -u 9
  echo "Verification lease expired and rollback failed; evidence preserved" >&2
  return 1
}

case "`${1:-deploy}" in
  deploy) deploy ;;
  rollback) rollback_transaction ;;
  commit) load_state; commit_deployment ;;
  expire) expire_lease ;;
  *) echo "unknown deployment action" >&2; exit 2 ;;
esac
"@

if ($RenderRemoteScriptPath) {
    Set-Content -LiteralPath $RenderRemoteScriptPath -Value $remoteBody -Encoding UTF8
    return
}
Set-Content -LiteralPath $localRemoteScript -Value $remoteBody -Encoding UTF8
$remoteStarted = $false
$remoteScriptLiteral = ConvertTo-ShellLiteral $remoteScript
$deployCommand = "bash $remoteScriptLiteral deploy"
$commitCommand = "bash $remoteScriptLiteral commit"
$rollbackCommand = "if [ -f $remoteScriptLiteral ]; then bash $remoteScriptLiteral rollback; fi"
try {
    Invoke-Checked scp $localRemoteScript "${RemoteHost}:$remoteScript"
    $remoteStarted = $true
    Invoke-Checked ssh $RemoteHost @($deployCommand)

    $health = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 20
    if ($health.StatusCode -ne 200) { throw "Health probe failed: HTTP $($health.StatusCode)" }
    $discovery = Invoke-WebRequest -Uri $DiscoveryUrl -UseBasicParsing -TimeoutSec 20
    if ($discovery.StatusCode -ne 200) { throw "Discovery probe failed: HTTP $($discovery.StatusCode)" }
    $metadata = $discovery.Content | ConvertFrom-Json
    if ($metadata.issuer -ne $ExpectedIssuer) {
        throw "Unexpected issuer in discovery document: $($metadata.issuer)"
    }

    Invoke-Checked ssh $RemoteHost @($commitCommand)
    $remoteStarted = $false
    Write-Host "Deployment verified: $image deployment-success"
}
catch {
    if ($remoteStarted) {
        & ssh $RemoteHost $rollbackCommand
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Automatic rollback command failed; inspect $RemoteHost immediately"
        }
    }
    throw
}
finally {
    Remove-Item -LiteralPath $localRemoteScript, $uiArchive, $archive -Force -ErrorAction SilentlyContinue
}
