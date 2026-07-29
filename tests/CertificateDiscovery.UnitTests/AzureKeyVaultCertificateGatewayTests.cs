using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Infrastructure.Deployment;

namespace CertificateDiscovery.UnitTests;

public sealed class AzureKeyVaultCertificateGatewayTests
{
    [Fact]
    public void Creates_password_protected_Pfx_with_matching_private_key()
    {
        var bundle = Bundle();

        var payload = AzureKeyVaultCertificateGateway.CreatePfx(bundle, "transient-password");

        try
        {
            Assert.NotEmpty(payload);
            Assert.Equal(X509ContentType.Pkcs12, X509Certificate2.GetCertContentType(payload));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    [Fact]
    public void Creates_Pem_with_certificate_and_unencrypted_PKCS8_private_key()
    {
        var bundle = Bundle();

        var payload = AzureKeyVaultCertificateGateway.CreatePem(bundle);

        Assert.Contains("BEGIN CERTIFICATE", payload);
        Assert.Contains("BEGIN PRIVATE KEY", payload);
        using var imported = X509Certificate2.CreateFromPem(payload, payload);
        Assert.Equal(bundle.Fingerprint, Convert.ToHexString(SHA256.HashData(imported.RawData)));
    }

    private static IssuedCertificateBundle Bundle()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=azure-key-vault.example.com",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddDays(30));
        var pem = certificate.ExportCertificatePem();
        return new(
            pem,
            key.ExportPkcs8PrivateKeyPem(),
            pem,
            Convert.ToHexString(SHA256.HashData(certificate.RawData)),
            5);
    }
}
