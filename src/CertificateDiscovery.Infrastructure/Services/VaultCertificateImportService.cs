namespace CertificateDiscovery.Infrastructure.Services;

using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

public sealed class VaultCertificateImportService(CertificateDiscoveryDbContext db, IHttpClientFactory httpClientFactory)
{
    public async Task<int> ImportPublicEndpointAsync(VaultServer server, CancellationToken cancellationToken)
    {
        try
        {
            if (!server.ScanPublicEndpoint) throw new InvalidOperationException("Public endpoint scan is disabled for this Vault server.");
            var chain = await ReadTlsChainAsync(server.BaseUrl, cancellationToken);
            if (chain.Count == 0) throw new InvalidOperationException("No certificate was returned by the Vault TLS endpoint.");
            await UpsertCertificateAsync(chain[0], chain, CertificateSource.VaultPublicEndpoint, server.Name, server.BaseUrl.ToString(), cancellationToken);
            await MarkSuccessAsync(server, 1, cancellationToken);
            return 1;
        }
        catch (Exception ex)
        {
            await MarkFailureAsync(server, ex.Message, cancellationToken);
            throw;
        }
    }

    public async Task<int> ImportPkiCertificatesAsync(VaultServer server, CancellationToken cancellationToken)
    {
        try
        {
            if (!server.ImportPkiCertificates) throw new InvalidOperationException("PKI import is disabled for this Vault server.");
            if (string.IsNullOrWhiteSpace(server.Token)) throw new InvalidOperationException("Vault token is required for PKI import.");
            if (string.IsNullOrWhiteSpace(server.PkiMountPath)) throw new InvalidOperationException("PKI mount path is required for PKI import.");

            var client = httpClientFactory.CreateClient();
            client.BaseAddress = server.BaseUrl;
            client.DefaultRequestHeaders.Add("X-Vault-Token", server.Token);

            var mount = server.PkiMountPath.Trim('/');
            using var listRequest = new HttpRequestMessage(HttpMethod.Get, $"/v1/{mount}/certs?list=true");
            using var listResponse = await client.SendAsync(listRequest, cancellationToken);
            listResponse.EnsureSuccessStatusCode();
            using var listJson = JsonDocument.Parse(await listResponse.Content.ReadAsStringAsync(cancellationToken));
            var keys = listJson.RootElement.GetProperty("data").GetProperty("keys").EnumerateArray().Select(x => x.GetString()).Where(x => !string.IsNullOrWhiteSpace(x)).ToList();

            var imported = 0;
            foreach (var key in keys)
            {
                using var certResponse = await client.GetAsync($"/v1/{mount}/cert/{Uri.EscapeDataString(key!)}", cancellationToken);
                certResponse.EnsureSuccessStatusCode();
                using var certJson = JsonDocument.Parse(await certResponse.Content.ReadAsStringAsync(cancellationToken));
                var data = certJson.RootElement.GetProperty("data");
                if (!data.TryGetProperty("certificate", out var certificateElement)) continue;
                var leaf = LoadCertificate(certificateElement.GetString());
                var chain = new List<X509Certificate2> { leaf };
                if (data.TryGetProperty("ca_chain", out var chainElement) && chainElement.ValueKind == JsonValueKind.Array)
                {
                    chain.AddRange(chainElement.EnumerateArray().Select(x => LoadCertificate(x.GetString())).Where(x => x.Thumbprint != leaf.Thumbprint));
                }

                await UpsertCertificateAsync(leaf, chain, CertificateSource.VaultPki, server.Name, $"{server.BaseUrl}/v1/{mount}/cert/{key}", cancellationToken);
                imported++;
            }

            await MarkSuccessAsync(server, imported, cancellationToken);
            return imported;
        }
        catch (Exception ex)
        {
            await MarkFailureAsync(server, ex.Message, cancellationToken);
            throw;
        }
    }

    private async Task<List<X509Certificate2>> ReadTlsChainAsync(Uri uri, CancellationToken cancellationToken)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(uri.Host, uri.Port > 0 ? uri.Port : 443, cancellationToken);
        using var stream = new SslStream(client.GetStream(), false, (_, _, _, _) => true);
        await stream.AuthenticateAsClientAsync(uri.Host);
        if (stream.RemoteCertificate is null) return [];

        var leaf = new X509Certificate2(stream.RemoteCertificate);
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
        chain.Build(leaf);
        var entries = chain.ChainElements.Count > 0
            ? chain.ChainElements.Cast<X509ChainElement>().Select(x => new X509Certificate2(x.Certificate)).ToList()
            : [leaf];
        return entries;
    }

    private async Task UpsertCertificateAsync(X509Certificate2 leaf, IReadOnlyList<X509Certificate2> chain, CertificateSource source, string sourceName, string externalReference, CancellationToken cancellationToken)
    {
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
        certificate.Source = source;
        certificate.SourceName = sourceName;
        certificate.ExternalReference = externalReference;
        certificate.PemEncodedCertificate = PemEncode(leaf);
        certificate.LastSeenAtUtc = DateTime.UtcNow;

        await db.CertificateSubjectAlternativeNames.Where(x => x.CertificateId == certificate.Id).ExecuteDeleteAsync(cancellationToken);
        foreach (var san in ExtractSans(leaf).DistinctBy(x => new { x.Name, x.Type }))
        {
            db.CertificateSubjectAlternativeNames.Add(new CertificateSubjectAlternativeName { CertificateId = certificate.Id, Name = san.Name, Type = san.Type });
        }

        await db.CertificateChainEntries.Where(x => x.CertificateId == certificate.Id).ExecuteDeleteAsync(cancellationToken);
        foreach (var entry in chain.Select((cert, index) => new { cert, index }).DistinctBy(x => x.index))
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
                PemEncodedCertificate = PemEncode(entry.cert),
                LastSeenAtUtc = DateTime.UtcNow
            });
        }

        await db.SaveChangesAsync(cancellationToken);
    }

    private static X509Certificate2 LoadCertificate(string? pem)
    {
        if (string.IsNullOrWhiteSpace(pem)) throw new InvalidOperationException("Vault returned an empty certificate.");
        return X509Certificate2.CreateFromPem(pem);
    }

    private static string Fingerprint(X509Certificate2 certificate) =>
        Convert.ToHexString(SHA256.HashData(certificate.RawData));

    private static string PemEncode(X509Certificate2 certificate) =>
        "-----BEGIN CERTIFICATE-----\n" +
        Convert.ToBase64String(certificate.RawData, Base64FormattingOptions.InsertLineBreaks) +
        "\n-----END CERTIFICATE-----\n";

    private static int? GetPublicKeySize(X509Certificate2 certificate) =>
        certificate.GetRSAPublicKey()?.KeySize ??
        certificate.GetECDsaPublicKey()?.KeySize ??
        certificate.GetDSAPublicKey()?.KeySize;

    private static IReadOnlyList<CertificateSubjectAlternativeName> ExtractSans(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        if (extension is null) return [];
        var values = new List<CertificateSubjectAlternativeName>();
        foreach (var dns in extension.EnumerateDnsNames()) values.Add(new CertificateSubjectAlternativeName { Name = dns, Type = CertificateSanType.DNS });
        foreach (var ip in extension.EnumerateIPAddresses()) values.Add(new CertificateSubjectAlternativeName { Name = ip.ToString(), Type = CertificateSanType.IP });
        return values;
    }

    private async Task MarkSuccessAsync(VaultServer server, int count, CancellationToken cancellationToken)
    {
        server.LastSyncAtUtc = DateTime.UtcNow;
        server.LastSyncStatus = $"Imported {count} certificate(s)";
        server.LastSyncError = null;
        server.UpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
    }

    private async Task MarkFailureAsync(VaultServer server, string error, CancellationToken cancellationToken)
    {
        server.LastSyncAtUtc = DateTime.UtcNow;
        server.LastSyncStatus = "Failed";
        server.LastSyncError = error;
        server.UpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
    }
}
