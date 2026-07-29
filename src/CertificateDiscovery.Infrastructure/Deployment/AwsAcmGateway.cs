using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Amazon.CertificateManager;
using Amazon.CertificateManager.Model;
using CertificateDiscovery.Application.Deployment;

namespace CertificateDiscovery.Infrastructure.Deployment;

public sealed record AwsAcmCertificateState(
    string CertificateArn,
    string Type,
    string Status,
    string? DomainName,
    DateTime? NotBefore,
    DateTime? NotAfter,
    IReadOnlyList<string> InUseBy);

public interface IAwsAcmGateway
{
    Task<AwsAcmCertificateState?> DescribeAsync(
        AwsAcmTargetOptions options,
        string? externalId,
        string certificateArn,
        CancellationToken cancellationToken);

    Task<string> ImportAsync(
        AwsAcmTargetOptions options,
        string? externalId,
        string? certificateArn,
        IssuedCertificateBundle bundle,
        CancellationToken cancellationToken);

    Task<string> GetFingerprintAsync(
        AwsAcmTargetOptions options,
        string? externalId,
        string certificateArn,
        CancellationToken cancellationToken);
}

public sealed class AwsAcmGateway(IAwsAcmClientFactory clients) : IAwsAcmGateway
{
    public async Task<AwsAcmCertificateState?> DescribeAsync(
        AwsAcmTargetOptions options,
        string? externalId,
        string certificateArn,
        CancellationToken cancellationToken)
    {
        using var client = await clients.CreateAsync(options, externalId, cancellationToken);
        try
        {
            var response = await client.DescribeCertificateAsync(
                new DescribeCertificateRequest { CertificateArn = certificateArn },
                cancellationToken);
            var certificate = response.Certificate;
            return certificate is null
                ? null
                : new(
                    certificate.CertificateArn,
                    certificate.Type?.Value ?? string.Empty,
                    certificate.Status?.Value ?? string.Empty,
                    certificate.DomainName,
                    certificate.NotBefore,
                    certificate.NotAfter,
                    certificate.InUseBy ?? []);
        }
        catch (ResourceNotFoundException)
        {
            return null;
        }
    }

    public async Task<string> ImportAsync(
        AwsAcmTargetOptions options,
        string? externalId,
        string? certificateArn,
        IssuedCertificateBundle bundle,
        CancellationToken cancellationToken)
    {
        ValidateBundle(bundle);
        var certificateBytes = Encoding.ASCII.GetBytes(bundle.CertificatePem);
        var privateKeyBytes = Encoding.ASCII.GetBytes(bundle.PrivateKeyPem);
        var chainBytes = Encoding.ASCII.GetBytes(IntermediateChainOnly(bundle.FullChainPem));
        try
        {
            using var client = await clients.CreateAsync(options, externalId, cancellationToken);
            using var certificate = new MemoryStream(certificateBytes, writable: false);
            using var privateKey = new MemoryStream(privateKeyBytes, writable: false);
            var request = new ImportCertificateRequest
            {
                Certificate = certificate,
                PrivateKey = privateKey,
                CertificateArn = certificateArn
            };
            using var chain = chainBytes.Length == 0 ? null : new MemoryStream(chainBytes, writable: false);
            if (chain is not null)
                request.CertificateChain = chain;
            if (certificateArn is null)
                request.Tags = options.Tags.Select(x => new Tag { Key = x.Key, Value = x.Value }).ToList();
            var response = await client.ImportCertificateAsync(request, cancellationToken);
            if (string.IsNullOrWhiteSpace(response.CertificateArn))
                throw new InvalidOperationException("AWS ACM import did not return a certificate ARN.");
            if (certificateArn is not null && options.Tags.Count > 0)
                await client.AddTagsToCertificateAsync(new AddTagsToCertificateRequest
                {
                    CertificateArn = response.CertificateArn,
                    Tags = options.Tags.Select(x => new Tag { Key = x.Key, Value = x.Value }).ToList()
                }, cancellationToken);
            return response.CertificateArn;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(certificateBytes);
            CryptographicOperations.ZeroMemory(privateKeyBytes);
            CryptographicOperations.ZeroMemory(chainBytes);
        }
    }

    public async Task<string> GetFingerprintAsync(
        AwsAcmTargetOptions options,
        string? externalId,
        string certificateArn,
        CancellationToken cancellationToken)
    {
        using var client = await clients.CreateAsync(options, externalId, cancellationToken);
        var response = await client.GetCertificateAsync(
            new GetCertificateRequest { CertificateArn = certificateArn },
            cancellationToken);
        if (string.IsNullOrWhiteSpace(response.Certificate))
            throw new InvalidOperationException("AWS ACM did not return certificate material for verification.");
        using var certificate = X509Certificate2.CreateFromPem(response.Certificate);
        return Convert.ToHexString(SHA256.HashData(certificate.RawData));
    }

    private static void ValidateBundle(IssuedCertificateBundle bundle)
    {
        using var certificate = X509Certificate2.CreateFromPem(bundle.CertificatePem, bundle.PrivateKeyPem);
        var fingerprint = Convert.ToHexString(SHA256.HashData(certificate.RawData));
        if (!string.Equals(fingerprint, bundle.Fingerprint, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Vault certificate fingerprint does not match the deployment bundle.");
    }

    private static string IntermediateChainOnly(string fullChainPem)
    {
        var blocks = new List<string>();
        var offset = 0;
        const string begin = "-----BEGIN CERTIFICATE-----";
        const string end = "-----END CERTIFICATE-----";
        while (true)
        {
            var start = fullChainPem.IndexOf(begin, offset, StringComparison.Ordinal);
            if (start < 0) break;
            var finish = fullChainPem.IndexOf(end, start, StringComparison.Ordinal);
            if (finish < 0)
                throw new InvalidOperationException("Vault certificate chain contains an invalid PEM block.");
            finish += end.Length;
            blocks.Add(fullChainPem[start..finish]);
            offset = finish;
        }
        return blocks.Count <= 1 ? string.Empty : string.Join(Environment.NewLine, blocks.Skip(1));
    }
}
