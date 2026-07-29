using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertificateDiscovery.Application.Inventory;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CertificateDiscovery.Infrastructure.Inventory;

public sealed class CertificateInventoryWriter(CertificateDiscoveryDbContext db) : ICertificateInventoryWriter
{
    public async Task<Guid> UpsertAsync(CertificateInventoryContext context, CancellationToken cancellationToken)
    {
        var leaf = X509Certificate2.CreateFromPem(context.CertificatePem);
        var chain = ParsePemCertificates(context.FullChainPem);
        if (chain.Count == 0) chain.Add(leaf);
        var fingerprint = Fingerprint(leaf);
        var certificate = await db.Certificates.FirstOrDefaultAsync(x => x.FingerprintSha256 == fingerprint, cancellationToken);
        if (certificate is null)
        {
            certificate = new Certificate { FingerprintSha256 = fingerprint };
            db.Certificates.Add(certificate);
        }

        certificate.SerialNumber = leaf.SerialNumber;
        certificate.Subject = leaf.Subject;
        certificate.CommonName = leaf.GetNameInfo(X509NameType.SimpleName, false);
        certificate.Issuer = leaf.Issuer;
        certificate.NotBeforeUtc = leaf.NotBefore.ToUniversalTime();
        certificate.NotAfterUtc = leaf.NotAfter.ToUniversalTime();
        certificate.SignatureAlgorithm = leaf.SignatureAlgorithm.FriendlyName;
        certificate.PublicKeyAlgorithm = leaf.PublicKey.Oid.FriendlyName;
        certificate.PublicKeySize = GetPublicKeySize(leaf);
        certificate.Version = leaf.Version;
        certificate.IsSelfSigned = leaf.Subject == leaf.Issuer;
        certificate.Source = CertificateSource.Acme;
        certificate.SourceName = context.AcmeProvider?.Name;
        certificate.ExternalReference = context.Request.VaultSecretPath;
        // Managed certificates are represented in the database by metadata only.
        // Their certificate and key material lives exclusively in Vault.
        certificate.PemEncodedCertificate = null;
        certificate.LastSeenAtUtc = DateTime.UtcNow;

        await db.SaveChangesAsync(cancellationToken);
        await db.CertificateSubjectAlternativeNames.Where(x => x.CertificateId == certificate.Id).ExecuteDeleteAsync(cancellationToken);
        foreach (var name in context.Domains.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            db.CertificateSubjectAlternativeNames.Add(new CertificateSubjectAlternativeName { CertificateId = certificate.Id, Name = name, Type = CertificateSanType.DNS });
        }

        await db.CertificateChainEntries.Where(x => x.CertificateId == certificate.Id).ExecuteDeleteAsync(cancellationToken);
        foreach (var entry in chain.Select((cert, index) => new { cert, index }))
        {
            db.CertificateChainEntries.Add(new CertificateChainEntry
            {
                CertificateId = certificate.Id,
                Position = entry.index,
                FingerprintSha256 = Fingerprint(entry.cert),
                SerialNumber = entry.cert.SerialNumber,
                Subject = entry.cert.Subject,
                CommonName = entry.cert.GetNameInfo(X509NameType.SimpleName, false),
                Issuer = entry.cert.Issuer,
                NotBeforeUtc = entry.cert.NotBefore.ToUniversalTime(),
                NotAfterUtc = entry.cert.NotAfter.ToUniversalTime(),
                SignatureAlgorithm = entry.cert.SignatureAlgorithm.FriendlyName,
                PublicKeyAlgorithm = entry.cert.PublicKey.Oid.FriendlyName,
                PublicKeySize = GetPublicKeySize(entry.cert),
                Version = entry.cert.Version,
                IsSelfSigned = entry.cert.Subject == entry.cert.Issuer,
                PemEncodedCertificate = null,
                LastSeenAtUtc = DateTime.UtcNow
            });
        }

        await db.SaveChangesAsync(cancellationToken);
        return certificate.Id;
    }

    private static List<X509Certificate2> ParsePemCertificates(string pem)
    {
        var certificates = new List<X509Certificate2>();
        const string begin = "-----BEGIN CERTIFICATE-----";
        const string end = "-----END CERTIFICATE-----";
        var index = 0;
        while (true)
        {
            var start = pem.IndexOf(begin, index, StringComparison.Ordinal);
            if (start < 0) break;
            var finish = pem.IndexOf(end, start, StringComparison.Ordinal);
            if (finish < 0) break;
            finish += end.Length;
            certificates.Add(X509Certificate2.CreateFromPem(pem.Substring(start, finish - start)));
            index = finish;
        }

        return certificates;
    }

    private static string Fingerprint(X509Certificate2 certificate) => Convert.ToHexString(SHA256.HashData(certificate.RawData));
    private static int? GetPublicKeySize(X509Certificate2 certificate) => certificate.GetRSAPublicKey()?.KeySize ?? certificate.GetECDsaPublicKey()?.KeySize ?? certificate.GetDSAPublicKey()?.KeySize;
}
