param(
    [switch]$Once,
    [string]$Iwatobi = (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads\iwatobi-0.1.0-win-x64\iwatobi-0.1.0-win-x64.exe')
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$bridgeArguments = @('-3', 'daily.py', '--config', 'config.local.json', '--prompt-secrets', '--iwatobi', $Iwatobi)
if (-not $Once) { $bridgeArguments += '--repeat' }
py @bridgeArguments
if ($LASTEXITCODE -ne 0) { throw "Collector stopped: exit code $LASTEXITCODE" }
