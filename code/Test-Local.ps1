$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
py -3 test_local.py
if ($LASTEXITCODE -ne 0) { throw "Local tests failed: exit code $LASTEXITCODE" }
