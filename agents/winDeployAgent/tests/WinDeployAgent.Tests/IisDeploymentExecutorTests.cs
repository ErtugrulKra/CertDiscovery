using Microsoft.Extensions.Logging.Abstractions;
using WinDeployAgent;
using Xunit;

namespace WinDeployAgent.Tests;

public sealed class IisDeploymentExecutorTests
{
    [Fact]
    public async Task Applies_and_verifies_binding_while_preserving_snapshot()
    {
        var certificateStore = new FakeCertificateStore();
        var bindingStore = new FakeBindingStore();
        var executor = new IisDeploymentExecutor(
            certificateStore, bindingStore, new FakeCcsStore(), NullLogger<IisDeploymentExecutor>.Instance);

        var result = await executor.ExecuteAsync(
            Bundle(),
            Target(),
            default);

        Assert.True(result.Succeeded);
        Assert.False(result.RolledBack);
        Assert.Equal(Fingerprint, result.ObservedFingerprint);
        Assert.Equal("OLD-SHA256", result.PreviousFingerprint);
        Assert.Equal(1, bindingStore.ApplyCount);
        Assert.Equal(0, bindingStore.RestoreCount);
        Assert.Equal("*:443:example.com", bindingStore.Snapshot.BindingInformation);
        Assert.Equal(1, bindingStore.Snapshot.SslFlags);
    }

    [Fact]
    public async Task Restores_previous_binding_and_removes_imported_certificate_when_verification_fails()
    {
        var certificateStore = new FakeCertificateStore();
        var bindingStore = new FakeBindingStore { VerificationSucceeds = false };
        var executor = new IisDeploymentExecutor(
            certificateStore, bindingStore, new FakeCcsStore(), NullLogger<IisDeploymentExecutor>.Instance);

        var result = await executor.ExecuteAsync(Bundle(), Target(), default);

        Assert.False(result.Succeeded);
        Assert.True(result.RolledBack);
        Assert.Equal("IisValidationFailed", result.ErrorCode);
        Assert.Equal(1, bindingStore.RestoreCount);
        Assert.Single(certificateStore.Removed);
    }

    [Fact]
    public async Task Replaces_and_verifies_ccs_file()
    {
        var ccs = new FakeCcsStore();
        var executor = new IisDeploymentExecutor(
            new FakeCertificateStore(), new FakeBindingStore { CentralCertificateStore = true },
            ccs, NullLogger<IisDeploymentExecutor>.Instance);

        var result = await executor.ExecuteAsync(Bundle(), CcsTarget(), default);

        Assert.True(result.Succeeded);
        Assert.Equal(1, ccs.ReplaceCount);
        Assert.Equal(0, ccs.RestoreCount);
    }

    [Fact]
    public async Task Restores_previous_ccs_file_when_verification_fails()
    {
        var ccs = new FakeCcsStore { Fingerprint = "WRONG" };
        var executor = new IisDeploymentExecutor(
            new FakeCertificateStore(), new FakeBindingStore { CentralCertificateStore = true },
            ccs, NullLogger<IisDeploymentExecutor>.Instance);

        var result = await executor.ExecuteAsync(Bundle(), CcsTarget(), default);

        Assert.False(result.Succeeded);
        Assert.True(result.RolledBack);
        Assert.Equal(1, ccs.RestoreCount);
    }

    private const string Fingerprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private static AgentJobProcessor.AgentCertificateBundle Bundle() =>
        new(Convert.ToBase64String([1, 2, 3]), "password", Fingerprint);
    private static string Target() =>
        """
        {
          "siteName": "Default Web Site",
          "bindingProtocol": "https",
          "bindingIpAddress": "*",
          "bindingPort": 443,
          "bindingHost": "example.com",
          "sniEnabled": true,
          "certificateStoreName": "My",
          "certificateStoreLocation": "LocalMachine",
          "deploymentMode": "Binding",
          "applicationPool": "DefaultAppPool",
          "restartApplicationPool": false
        }
        """;
    private static string CcsTarget() =>
        """
        {
          "siteName": "Default Web Site",
          "bindingProtocol": "https",
          "bindingIpAddress": "*",
          "bindingPort": 443,
          "bindingHost": "example.com",
          "sniEnabled": true,
          "certificateStoreName": "My",
          "certificateStoreLocation": "LocalMachine",
          "deploymentMode": "CentralCertificateStore",
          "centralCertificateStorePath": "C:\\certs",
          "pfxFileName": "example.com.pfx",
          "restartApplicationPool": false
        }
        """;

    private sealed class FakeCertificateStore : IWindowsCertificateStore
    {
        public List<byte[]> Removed { get; } = [];
        public CertificateImportResult Import(byte[] pfx, string password, string storeName) =>
            new([9, 9, 9], Fingerprint, [[9, 9, 9]]);
        public string? FindSha256Fingerprint(byte[]? bindingHash, string? storeName) => "OLD-SHA256";
        public void Remove(IReadOnlyList<byte[]> certificateHashes, string storeName) =>
            Removed.AddRange(certificateHashes);
    }

    private sealed class FakeBindingStore : IIisBindingStore
    {
        public bool VerificationSucceeds { get; init; } = true;
        public bool CentralCertificateStore { get; init; }
        public int ApplyCount { get; private set; }
        public int RestoreCount { get; private set; }
        public IisBindingSnapshot Snapshot { get; } =
            new("Default Web Site", "*:443:example.com", "https", [1, 1, 1], "My", 1, "DefaultAppPool");

        public IisBindingSnapshot Capture(IisTargetOptions options) => Snapshot;
        public void Apply(IisBindingSnapshot snapshot, byte[] certificateHash, string certificateStoreName, bool recycleApplicationPool) =>
            ApplyCount++;
        public void Restore(IisBindingSnapshot snapshot, bool recycleApplicationPool) => RestoreCount++;
        public bool IsApplied(IisBindingSnapshot snapshot, byte[] certificateHash, string certificateStoreName) =>
            RestoreCount > 0 || VerificationSucceeds;
        public bool UsesCentralCertificateStore(IisBindingSnapshot snapshot) => CentralCertificateStore;
    }

    private sealed class FakeCcsStore : ICentralCertificateStore
    {
        public string Fingerprint { get; init; } = IisDeploymentExecutorTests.Fingerprint;
        public int ReplaceCount { get; private set; }
        public int RestoreCount { get; private set; }
        public CcsFileSnapshot Replace(byte[] pfx, string password, IisTargetOptions options)
        {
            ReplaceCount++;
            return new("certificate.pfx", "certificate.bak", true);
        }
        public string VerifyFingerprint(CcsFileSnapshot snapshot, string password) => Fingerprint;
        public void Restore(CcsFileSnapshot snapshot) => RestoreCount++;
    }
}
