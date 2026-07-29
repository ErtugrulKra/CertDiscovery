using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WinDeployAgent;
using Xunit;

namespace WinDeployAgent.Tests;

public sealed class MicrosoftIisIntegrationTests
{
    [Fact]
    public void Replaces_verifies_and_restores_a_real_isolated_iis_binding_when_enabled()
    {
        var targetJson = Environment.GetEnvironmentVariable("WINDEPLOYAGENT_IIS_TEST_TARGET_JSON");
        if (string.IsNullOrWhiteSpace(targetJson))
            return;

        var options = IisTargetOptions.Parse(targetJson);
        Assert.Equal("Binding", options.DeploymentMode, ignoreCase: true);
        var bindings = new MicrosoftIisBindingStore();
        var certificates = new WindowsCertificateStore();
        var snapshot = bindings.Capture(options);
        var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        var pfx = CreatePfx(
            string.IsNullOrWhiteSpace(options.BindingHost) ? "agent-test.local" : options.BindingHost,
            password);
        CertificateImportResult? imported = null;
        try
        {
            imported = certificates.Import(pfx, password, options.CertificateStoreName);
            bindings.Apply(snapshot, imported.BindingHash, options.CertificateStoreName, recycleApplicationPool: false);
            var applied = bindings.Capture(options);
            Assert.Equal(Convert.ToHexString(imported.BindingHash), Convert.ToHexString(applied.CertificateHash ?? []));
            Assert.Equal(options.CertificateStoreName, applied.CertificateStoreName, ignoreCase: true);
            Assert.Equal(snapshot.BindingInformation, applied.BindingInformation);
            Assert.Equal(snapshot.SslFlags, applied.SslFlags);
        }
        finally
        {
            if (imported is not null)
            {
                bindings.Restore(snapshot, recycleApplicationPool: false);
                certificates.Remove(imported.AddedCertificateHashes, options.CertificateStoreName);
            }
            CryptographicOperations.ZeroMemory(pfx);
        }
    }

    private static byte[] CreatePfx(string host, string password)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={host}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        return certificate.Export(X509ContentType.Pfx, password);
    }
}
