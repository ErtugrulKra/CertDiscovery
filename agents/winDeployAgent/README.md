# winDeployAgent

This is an independent Windows-only solution for CertDiscovery Microsoft IIS deployments.
It is intentionally not referenced by `CertificateDiscovery.sln`.

Build:

```powershell
dotnet build .\winDeployAgent.sln
```

Publish the standalone executable:

```powershell
dotnet publish .\src\WinDeployAgent.Service\WinDeployAgent.Service.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

On first start, configure `Agent:CentralUrl`. When `Agent:RegistrationToken` is
empty, the agent starts an administrator-approved exchange, prints an approval
code and Central verification URL, and waits for approval. The pending exchange,
resulting agent token and private key are stored with Windows DPAPI machine scope
and are not written to application logs. A short-lived one-time
`Agent:RegistrationToken` remains available for unattended provisioning.

## Microsoft IIS binding mode

The agent:

- pulls only jobs assigned to its registered identity;
- renews the job lease while deployment is running;
- downloads a transient bundle sourced by Central directly from Vault;
- decrypts the bundle in memory and never writes a temporary PFX;
- imports the certificate into the configured `LocalMachine` store;
- updates the exact HTTPS binding through `Microsoft.Web.Administration`;
- preserves binding information and SSL/SNI flags;
- verifies the bound certificate hash locally;
- restores the previous binding and removes certificates added by the failed
  attempt when rollback is required.

The Windows Service identity must be allowed to manage the selected certificate
store and IIS configuration. Binding mode currently supports `LocalMachine`.
Central Certificate Store is intentionally rejected until its separate atomic
file deployment and rollback executor is enabled.

An IIS-host integration test still requires a Windows test machine with the IIS
management components installed. The solution's unit tests use isolated store
and binding adapters and do not modify the developer machine.
