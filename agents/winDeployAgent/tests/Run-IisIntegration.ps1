param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path,
    [string]$LogPath = (Join-Path $PSScriptRoot 'iis-integration.log')
)

$ErrorActionPreference = 'Stop'
Start-Transcript -Path $LogPath -Force | Out-Null
$siteName = 'CertDiscovery-Agent-Test'
$siteRoot = Join-Path $PSScriptRoot 'iis-site'
$appCmd = Join-Path $env:windir 'System32\inetsrv\appcmd.exe'
$target = @{
    siteName = $siteName
    bindingProtocol = 'https'
    bindingIpAddress = '*'
    bindingPort = 44443
    bindingHost = ''
    sniEnabled = $false
    certificateStoreName = 'My'
    certificateStoreLocation = 'LocalMachine'
    deploymentMode = 'Binding'
    restartApplicationPool = $false
} | ConvertTo-Json -Compress

New-Item -ItemType Directory -Path $siteRoot -Force | Out-Null
try {
    & $appCmd add site "/name:$siteName" '/bindings:https/*:44443:' "/physicalPath:$siteRoot"
    if ($LASTEXITCODE -ne 0) { throw "Unable to create isolated Microsoft IIS test site." }

    $env:WINDEPLOYAGENT_IIS_TEST_TARGET_JSON = $target
    dotnet test (Join-Path $RepositoryRoot 'agents\winDeployAgent\tests\WinDeployAgent.Tests\WinDeployAgent.Tests.csproj') `
        --filter MicrosoftIisIntegrationTests
    if ($LASTEXITCODE -ne 0) { throw "Microsoft IIS integration test failed." }
}
finally {
    Remove-Item Env:WINDEPLOYAGENT_IIS_TEST_TARGET_JSON -ErrorAction SilentlyContinue
    & $appCmd delete site "/site.name:$siteName" | Out-Null
    Stop-Transcript | Out-Null
}
