using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Azure;
using Azure.Security.KeyVault.Certificates;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Domain;

namespace CertificateDiscovery.Infrastructure.Deployment;

public sealed record AzureKeyVaultCertificateState(
    string CertificateUri,
    string Name,
    string Version,
    string Fingerprint,
    string ContentType,
    bool? Enabled,
    DateTimeOffset? NotBefore,
    DateTimeOffset? ExpiresOn,
    IReadOnlyDictionary<string, string> Tags);

public interface IAzureKeyVaultCertificateGateway
{
    Task<AzureKeyVaultCertificateState?> GetCurrentAsync(
        AzureKeyVaultTargetOptions options,
        string? clientSecret,
        CancellationToken cancellationToken);

    Task<AzureKeyVaultCertificateState> ImportAsync(
        AzureKeyVaultTargetOptions options,
        string? clientSecret,
        IssuedCertificateBundle bundle,
        CancellationToken cancellationToken);
}

public sealed class AzureKeyVaultCertificateGateway(
    IAzureKeyVaultCertificateClientFactory clients) : IAzureKeyVaultCertificateGateway
{
    public async Task<AzureKeyVaultCertificateState?> GetCurrentAsync(
        AzureKeyVaultTargetOptions options,
        string? clientSecret,
        CancellationToken cancellationToken)
    {
        var client = clients.Create(options, clientSecret);
        try
        {
            var response = await client.GetCertificateAsync(options.CertificateName, cancellationToken);
            return State(response.Value);
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return null;
        }
    }

    public async Task<AzureKeyVaultCertificateState> ImportAsync(
        AzureKeyVaultTargetOptions options,
        string? clientSecret,
        IssuedCertificateBundle bundle,
        CancellationToken cancellationToken)
    {
        ValidateBundle(bundle);
        byte[]? payload = null;
        string? password = null;
        try
        {
            if (options.ImportFormat == AzureKeyVaultImportFormat.Pfx)
            {
                password = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
                payload = CreatePfx(bundle, password);
            }
            else
            {
                payload = Encoding.ASCII.GetBytes(CreatePem(bundle));
            }
            var policy = new CertificatePolicy
            {
                ContentType = options.ImportFormat == AzureKeyVaultImportFormat.Pfx
                    ? CertificateContentType.Pkcs12
                    : CertificateContentType.Pem
            };
            var import = new ImportCertificateOptions(options.CertificateName, payload)
            {
                Password = password,
                Enabled = options.Enabled,
                PreserveCertificateOrder = options.PreserveCertificateOrder,
                Policy = policy
            };
            foreach (var tag in ManagedTags(options, bundle))
                import.Tags[tag.Key] = tag.Value;
            var client = clients.Create(options, clientSecret);
            var response = await client.ImportCertificateAsync(import, cancellationToken);
            return State(response.Value);
        }
        finally
        {
            if (payload is not null)
                CryptographicOperations.ZeroMemory(payload);
            password = null;
        }
    }

    private static AzureKeyVaultCertificateState State(KeyVaultCertificateWithPolicy certificate)
    {
        if (certificate.Cer is null || certificate.Cer.Length == 0)
            throw new InvalidOperationException("Azure Key Vault did not return public certificate material.");
        var fingerprint = Convert.ToHexString(SHA256.HashData(certificate.Cer));
        var properties = certificate.Properties;
        return new(
            certificate.Id.ToString(),
            certificate.Name,
            properties.Version ?? string.Empty,
            fingerprint,
            certificate.Policy?.ContentType?.ToString() ?? string.Empty,
            properties.Enabled,
            properties.NotBefore,
            properties.ExpiresOn,
            new Dictionary<string, string>(properties.Tags, StringComparer.Ordinal));
    }

    private static IReadOnlyDictionary<string, string> ManagedTags(
        AzureKeyVaultTargetOptions options,
        IssuedCertificateBundle bundle)
    {
        var tags = new Dictionary<string, string>(options.Tags, StringComparer.Ordinal)
        {
            ["certdiscovery-managed-by"] = "CertDiscovery",
            ["certdiscovery-fingerprint"] = bundle.Fingerprint
        };
        if (bundle.VaultVersion is not null)
            tags["certdiscovery-source-vault-version"] = bundle.VaultVersion.Value.ToString();
        return tags;
    }

    private static void ValidateBundle(IssuedCertificateBundle bundle)
    {
        using var certificate = X509Certificate2.CreateFromPem(bundle.CertificatePem, bundle.PrivateKeyPem);
        var fingerprint = Convert.ToHexString(SHA256.HashData(certificate.RawData));
        if (!string.Equals(fingerprint, bundle.Fingerprint, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Vault certificate fingerprint does not match the deployment bundle.");
    }

    internal static byte[] CreatePfx(IssuedCertificateBundle bundle, string password)
    {
        using var leaf = X509Certificate2.CreateFromPem(bundle.CertificatePem, bundle.PrivateKeyPem);
        var collection = new X509Certificate2Collection { leaf };
        foreach (var pem in CertificateBlocks(bundle.FullChainPem).Skip(1))
            collection.Add(X509Certificate2.CreateFromPem(pem));
        try
        {
            return collection.Export(X509ContentType.Pkcs12, password)
                   ?? throw new InvalidOperationException("Could not create the transient PFX payload.");
        }
        finally
        {
            foreach (var certificate in collection.Cast<X509Certificate2>().Skip(1))
                certificate.Dispose();
        }
    }

    internal static string CreatePem(IssuedCertificateBundle bundle)
    {
        var certificates = CertificateBlocks(bundle.FullChainPem);
        if (certificates.Count == 0)
            certificates.Add(bundle.CertificatePem.Trim());
        return string.Join(Environment.NewLine, certificates) +
               Environment.NewLine +
               bundle.PrivateKeyPem.Trim() +
               Environment.NewLine;
    }

    private static List<string> CertificateBlocks(string pem)
    {
        var blocks = new List<string>();
        var offset = 0;
        const string begin = "-----BEGIN CERTIFICATE-----";
        const string end = "-----END CERTIFICATE-----";
        while (true)
        {
            var start = pem.IndexOf(begin, offset, StringComparison.Ordinal);
            if (start < 0) break;
            var finish = pem.IndexOf(end, start, StringComparison.Ordinal);
            if (finish < 0)
                throw new InvalidOperationException("Vault certificate chain contains an invalid PEM block.");
            finish += end.Length;
            blocks.Add(pem[start..finish]);
            offset = finish;
        }
        return blocks;
    }
}
