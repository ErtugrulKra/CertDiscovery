# winDeployAgent validation

Unit tests run with:

```powershell
dotnet test .\agents\winDeployAgent\tests\WinDeployAgent.Tests\WinDeployAgent.Tests.csproj
```

The real Microsoft IIS binding integration test is deliberately opt-in because
it changes and then restores a binding and therefore requires an elevated
Windows test machine. Create a dedicated test site/binding, then provide its
configuration:

```powershell
$env:WINDEPLOYAGENT_IIS_TEST_TARGET_JSON = '{"siteName":"CertDiscovery-Agent-Test","bindingProtocol":"https","bindingIpAddress":"*","bindingPort":44443,"bindingHost":"agent-test.local","sniEnabled":true,"certificateStoreName":"My","certificateStoreLocation":"LocalMachine","deploymentMode":"Binding","restartApplicationPool":false}'
dotnet test .\agents\winDeployAgent\tests\WinDeployAgent.Tests\WinDeployAgent.Tests.csproj --filter MicrosoftIisIntegrationTests
```

The test generates an in-memory self-signed PFX, imports it into `LocalMachine`,
updates and verifies the binding through `Microsoft.Web.Administration`, then
restores the original binding and removes the generated certificate.
