$ErrorActionPreference = 'Stop'
$root = (Resolve-Path $PSScriptRoot).Path
$runtime = Join-Path $root 'runtime'
if (-not $runtime.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Unsafe P5.5 integration runtime path.'
}

if (Test-Path -LiteralPath $runtime) {
    Remove-Item -LiteralPath $runtime -Recurse -Force
}
New-Item -ItemType Directory -Path $runtime | Out-Null
$privateKey = Join-Path $runtime 'id_ed25519'
ssh-keygen -q -t ed25519 -N '""' -f $privateKey
Copy-Item -LiteralPath "$privateKey.pub" -Destination (Join-Path $runtime 'authorized_keys')

try {
    docker compose -f (Join-Path $root 'docker-compose.yml') up -d --build
    if ($LASTEXITCODE -ne 0) { throw 'P5.5 SSH integration containers failed to start.' }

    foreach ($attempt in 1..30) {
        docker compose -f (Join-Path $root 'docker-compose.yml') exec -T nginx-ssh true 2>$null
        if ($LASTEXITCODE -eq 0) { break }
        Start-Sleep -Seconds 1
    }

    $nginxKey = docker compose -f (Join-Path $root 'docker-compose.yml') exec -T nginx-ssh `
        ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
    $apacheKey = docker compose -f (Join-Path $root 'docker-compose.yml') exec -T apache-ssh `
        ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
    $env:P55_Nginx_HOST_KEY = [regex]::Match(($nginxKey -join ' '), 'SHA256:[A-Za-z0-9+/]+').Value
    $env:P55_ApacheWebServer_HOST_KEY = [regex]::Match(($apacheKey -join ' '), 'SHA256:[A-Za-z0-9+/]+').Value
    $env:P55_SSH_PRIVATE_KEY = Get-Content -LiteralPath $privateKey -Raw
    if (-not $env:P55_Nginx_HOST_KEY -or -not $env:P55_ApacheWebServer_HOST_KEY) {
        throw 'Unable to determine pinned SSH host-key fingerprints.'
    }

    dotnet test (Join-Path $root '..\CertificateDiscovery.IntegrationTests\CertificateDiscovery.IntegrationTests.csproj') `
        --filter SshCertificateDeploymentIntegrationTests
    if ($LASTEXITCODE -ne 0) { throw 'P5.5 SSH integration tests failed.' }
}
finally {
    Remove-Item Env:P55_Nginx_HOST_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:P55_ApacheWebServer_HOST_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:P55_SSH_PRIVATE_KEY -ErrorAction SilentlyContinue
    docker compose -f (Join-Path $root 'docker-compose.yml') down -v
    if (Test-Path -LiteralPath $runtime) {
        Remove-Item -LiteralPath $runtime -Recurse -Force
    }
}
