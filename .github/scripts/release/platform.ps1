param(
    [Parameter(Mandatory)]
    [ValidateSet('check-msvc', 'smoke', 'check-windows', 'stage')]
    [string]$Phase
)

$ErrorActionPreference = 'Stop'

switch ($Phase) {
    'check-msvc' {
        cmake --version
        perl -v | Out-Null
        $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
        if (-not (Test-Path -LiteralPath $vswhere)) { throw "vswhere is unavailable" }
        $component = "$env:MSVC_COMPONENT"
        $installation = & $vswhere -latest -products * -requires $component -property installationPath
        if (-not $installation) { throw "MSVC build tools are unavailable" }
        $nmake = Get-ChildItem -LiteralPath "$installation\VC\Tools\MSVC" -Recurse -Filter nmake.exe | Select-Object -First 1
        if (-not $nmake) { throw "nmake is unavailable" }
        "MSVC_INSTALLATION=$installation" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append
    }

    'smoke' {
        $server = Resolve-Path "target/$env:RELEASE_TARGET/release/nazoauth$env:RELEASE_EXECUTABLE_SUFFIX"
        & $server --help
        if ($LASTEXITCODE -ne 0) { throw "nazoauth help smoke failed" }
        $identity = (& $server release-identity | ConvertFrom-Json)
        if ($LASTEXITCODE -ne 0) { throw "nazoauth release identity smoke failed" }
        $metadata = cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json
        $serverPackage = $metadata.packages | Where-Object { $_.name -eq "nazo-server" }
        if ($identity.release -ne "v$($serverPackage.version)") { throw "embedded release mismatch" }
        $protocolSource = Get-Content "crates/operator-protocol/src/lib.rs" -Raw
        $protocolMatch = [regex]::Match($protocolSource, 'pub const PROTOCOL_VERSION: u32 = (\d+);')
        if (!$protocolMatch.Success) { throw "unable to read the source protocol version" }
        if ($identity.protocol -ne [int]$protocolMatch.Groups[1].Value) { throw "embedded protocol mismatch" }
    }

    'check-windows' {
        if (-not $env:MSVC_INSTALLATION) { throw "verified MSVC installation is unavailable" }
        $dumpbin = Get-ChildItem -LiteralPath "$env:MSVC_INSTALLATION\VC\Tools\MSVC" -Recurse -Filter dumpbin.exe | Select-Object -First 1
        if (-not $dumpbin) { throw "dumpbin is unavailable" }
        $binary = "target/$env:RELEASE_TARGET/release/nazoauth.exe"
        $dependencies = & $dumpbin.FullName /DEPENDENTS $binary
        if ($LASTEXITCODE -ne 0) { throw "dumpbin failed for $binary" }
        if ($dependencies -match "(?i)(libpq|libssl|libcrypto|ssleay|libeay).*\.dll") {
          throw "$binary depends on a non-system database or TLS DLL"
        }
    }

    'stage' {
        New-Item -ItemType Directory -Force -Path "target/release-binaries" | Out-Null
        Copy-Item -LiteralPath "target/$env:RELEASE_TARGET/release/nazoauth$env:RELEASE_EXECUTABLE_SUFFIX" -Destination "target/release-binaries/nazoauth-$env:RELEASE_TARGET$env:RELEASE_EXECUTABLE_SUFFIX"
    }
}
