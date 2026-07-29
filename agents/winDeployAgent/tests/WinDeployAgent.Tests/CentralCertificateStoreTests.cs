using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WinDeployAgent;
using Xunit;

namespace WinDeployAgent.Tests;

public sealed class CentralCertificateStoreTests
{
    [Fact]
    public void Atomically_replaces_verifies_and_restores_existing_pfx()
    {
        var directory = Path.Combine(Path.GetTempPath(), "CertDiscovery", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var oldPfx = CreatePfx("old.example.com", out _, "secret");
            var newPfx = CreatePfx("example.com", out var fingerprint, "secret");
            var target = Path.Combine(directory, "example.com.pfx");
            File.WriteAllBytes(target, oldPfx);
            var store = new CentralCertificateStore();

            var snapshot = store.Replace(newPfx, "secret", Options(directory));

            Assert.Equal(fingerprint, store.VerifyFingerprint(snapshot, "secret"));
            Assert.NotNull(snapshot.BackupPath);
            Assert.True(File.Exists(snapshot.BackupPath));
            store.Restore(snapshot);
            Assert.Equal(oldPfx, File.ReadAllBytes(target));
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Rejects_a_file_name_that_does_not_match_the_binding_host()
    {
        var json =
            """{"siteName":"site","bindingPort":443,"bindingHost":"example.com","deploymentMode":"CentralCertificateStore","centralCertificateStorePath":"C:\\certs","pfxFileName":"other.pfx"}""";

        Assert.Throws<InvalidOperationException>(() => IisTargetOptions.Parse(json));
    }

    private static IisTargetOptions Options(string directory) =>
        IisTargetOptions.Parse(
            $$"""{"siteName":"site","bindingPort":443,"bindingHost":"example.com","deploymentMode":"CentralCertificateStore","centralCertificateStorePath":{{System.Text.Json.JsonSerializer.Serialize(directory)}},"pfxFileName":"example.com.pfx"}""");

    private static byte[] CreatePfx(string commonName, out string fingerprint, string password)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={commonName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        fingerprint = Convert.ToHexString(SHA256.HashData(certificate.RawData));
        return certificate.Export(X509ContentType.Pfx, password);
    }
}
