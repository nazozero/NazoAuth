$ErrorActionPreference = "Stop"

$scriptPath = Join-Path $PSScriptRoot "..\scripts\deploy_live.ps1"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    throw "deploy_live.ps1 has parse errors: $($parseErrors -join '; ')"
}

$function = $ast.Find(
    {
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq "ConvertTo-ShellWord"
    },
    $true
)
if ($null -eq $function) {
    throw "ConvertTo-ShellWord was not found"
}

Invoke-Expression $function.Extent.Text

$emptyLiteral = ConvertTo-ShellWord ""
if ($emptyLiteral -ne "''") {
    throw "empty shell literal must be two single quotes, got: $emptyLiteral"
}

$quotedLiteral = ConvertTo-ShellWord "a'b"
if ($quotedLiteral -ne "'a'\''b'") {
    throw "single quote escaping changed unexpectedly: $quotedLiteral"
}

# Exercise the real wrapper with an SSH stub: no remote action is performed.
function global:ssh {
    $global:DeployLiveCapturedSshArguments = @($args)
    $global:LASTEXITCODE = 0
}
$config = "/etc/nazo auth/a'b.json"
& $scriptPath -Action plan -SshHost audit-host -Config $config -Version "v1.2.3+build.4"
$expected = "'sudo' 'nazoauthctl' '--config' '/etc/nazo auth/a'\''b.json' 'update' '--plan' '--to' 'v1.2.3+build.4'"
if ($global:DeployLiveCapturedSshArguments[-1] -ne $expected) {
    throw "wrapper must preserve the config path and delegate release validation"
}
Write-Output "deploy_live shell literal and invocation tests passed"
