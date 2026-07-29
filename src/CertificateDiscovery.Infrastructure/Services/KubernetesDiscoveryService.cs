using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CertificateDiscovery.Application.Secrets;
using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CertificateDiscovery.Infrastructure.Services;

public sealed class KubernetesDiscoveryService(
    CertificateDiscoveryDbContext db,
    IHttpClientFactory httpClientFactory,
    ISecretProvider secretProvider)
{
    public async Task<KubernetesClusterDto?> GetAsync(Guid id, CancellationToken cancellationToken)
    {
        var cluster = await db.KubernetesClusters.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        return cluster is null ? null : ToDto(cluster);
    }

    public async Task CreateAsync(KubernetesClusterUpsertRequest request, CancellationToken cancellationToken)
    {
        Validate(request, tokenRequired: true);
        var name = request.Name.Trim();
        if (await db.KubernetesClusters.AnyAsync(x => x.Name == name, cancellationToken))
            throw new InvalidOperationException("A Kubernetes cluster with the same name already exists.");
        var cluster = new KubernetesCluster
        {
            Name = name,
            ApiServer = new Uri(request.ApiServer.Trim()),
            Description = Normalize(request.Description),
            Namespaces = NormalizeNamespaces(request.Namespaces),
            IsEnabled = request.IsEnabled
        };
        cluster.BearerTokenSecretReference = await secretProvider.StoreAsync(
            $"kubernetes-bearer-token:{cluster.Id:D}", request.BearerToken!.Trim(), cancellationToken);
        db.KubernetesClusters.Add(cluster);
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<bool> UpdateAsync(Guid id, KubernetesClusterUpsertRequest request, CancellationToken cancellationToken)
    {
        var cluster = await db.KubernetesClusters.FindAsync([id], cancellationToken);
        if (cluster is null) return false;
        Validate(request, tokenRequired: string.IsNullOrWhiteSpace(cluster.BearerTokenSecretReference));
        var name = request.Name.Trim();
        if (await db.KubernetesClusters.AnyAsync(x => x.Id != id && x.Name == name, cancellationToken))
            throw new InvalidOperationException("A Kubernetes cluster with the same name already exists.");
        cluster.Name = name;
        cluster.ApiServer = new Uri(request.ApiServer.Trim());
        cluster.Description = Normalize(request.Description);
        cluster.Namespaces = NormalizeNamespaces(request.Namespaces);
        cluster.IsEnabled = request.IsEnabled;
        cluster.UpdatedAtUtc = DateTime.UtcNow;
        if (!string.IsNullOrWhiteSpace(request.BearerToken))
        {
            var previous = cluster.BearerTokenSecretReference;
            cluster.BearerTokenSecretReference = await secretProvider.StoreAsync(
                $"kubernetes-bearer-token:{cluster.Id:D}", request.BearerToken.Trim(), cancellationToken);
            if (!string.IsNullOrWhiteSpace(previous)) await secretProvider.DeleteAsync(previous, cancellationToken);
        }
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task<bool> DeleteAsync(Guid id, CancellationToken cancellationToken)
    {
        var cluster = await db.KubernetesClusters.FindAsync([id], cancellationToken);
        if (cluster is null) return false;
        if (!string.IsNullOrWhiteSpace(cluster.BearerTokenSecretReference))
            await secretProvider.DeleteAsync(cluster.BearerTokenSecretReference, cancellationToken);
        db.KubernetesClusters.Remove(cluster);
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task<int?> DiscoverAsync(Guid id, CancellationToken cancellationToken)
    {
        var cluster = await db.KubernetesClusters.FindAsync([id], cancellationToken);
        if (cluster is null) return null;
        if (!cluster.IsEnabled) throw new InvalidOperationException("The Kubernetes cluster integration is disabled.");
        if (string.IsNullOrWhiteSpace(cluster.BearerTokenSecretReference))
            throw new InvalidOperationException("The Kubernetes bearer token is not configured.");

        try
        {
            var token = await secretProvider.GetAsync(cluster.BearerTokenSecretReference, cancellationToken);
            var imported = 0;
            foreach (var path in SecretListPaths(cluster.Namespaces))
            {
                var list = await ListSecretsAsync(cluster.ApiServer, path, token, cancellationToken);
                foreach (var secret in list.Items.Where(x =>
                             string.Equals(x.Type, "kubernetes.io/tls", StringComparison.Ordinal) &&
                             x.Data?.ContainsKey("tls.crt") == true))
                {
                    var certificateBytes = Convert.FromBase64String(secret.Data!["tls.crt"]);
                    var pem = Encoding.UTF8.GetString(certificateBytes);
                    var chain = ParsePemCertificates(pem);
                    if (chain.Count == 0) throw new CryptographicException("tls.crt does not contain a PEM certificate.");
                    await UpsertAsync(cluster, secret.Metadata.Namespace, secret.Metadata.Name, chain, cancellationToken);
                    imported++;
                }
            }
            cluster.LastSyncAtUtc = DateTime.UtcNow;
            cluster.LastSyncStatus = "Succeeded";
            cluster.LastSyncError = null;
            await db.SaveChangesAsync(cancellationToken);
            return imported;
        }
        catch (Exception ex)
        {
            cluster.LastSyncAtUtc = DateTime.UtcNow;
            cluster.LastSyncStatus = "Failed";
            cluster.LastSyncError = SafeError(ex);
            await db.SaveChangesAsync(CancellationToken.None);
            throw;
        }
    }

    private async Task<KubernetesSecretList> ListSecretsAsync(
        Uri apiServer, string path, string token, CancellationToken cancellationToken)
    {
        var client = httpClientFactory.CreateClient();
        client.BaseAddress = apiServer;
        var items = new List<KubernetesSecret>();
        string? continuation = null;
        do
        {
            var separator = path.Contains('?') ? '&' : '?';
            var requestPath = $"{path}{separator}limit=500";
            if (!string.IsNullOrWhiteSpace(continuation))
                requestPath += $"&continue={Uri.EscapeDataString(continuation)}";
            using var request = new HttpRequestMessage(HttpMethod.Get, requestPath);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var response = await client.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
                throw new InvalidOperationException($"Kubernetes Secret discovery failed with HTTP {(int)response.StatusCode}.");
            var page = await response.Content.ReadFromJsonAsync<KubernetesSecretList>(cancellationToken: cancellationToken)
                       ?? throw new InvalidOperationException("Kubernetes returned an invalid Secret list.");
            items.AddRange(page.Items);
            continuation = page.Metadata?.Continue;
        } while (!string.IsNullOrWhiteSpace(continuation));
        return new KubernetesSecretList(items, null);
    }

    private async Task UpsertAsync(
        KubernetesCluster cluster,
        string kubernetesNamespace,
        string secretName,
        IReadOnlyList<X509Certificate2> chain,
        CancellationToken cancellationToken)
    {
        var leaf = chain[0];
        var fingerprint = Fingerprint(leaf);
        var certificate = await db.Certificates.FirstOrDefaultAsync(
            x => x.FingerprintSha256 == fingerprint, cancellationToken);
        if (certificate is null)
        {
            certificate = new Certificate { FingerprintSha256 = fingerprint };
            db.Certificates.Add(certificate);
        }
        ApplyCertificate(certificate, leaf, cluster, kubernetesNamespace, secretName);
        await db.SaveChangesAsync(cancellationToken);

        await db.CertificateSubjectAlternativeNames.Where(x => x.CertificateId == certificate.Id)
            .ExecuteDeleteAsync(cancellationToken);
        foreach (var san in SubjectAlternativeNames(leaf))
            db.CertificateSubjectAlternativeNames.Add(new CertificateSubjectAlternativeName
            {
                CertificateId = certificate.Id, Name = san.Name, Type = san.Type
            });

        await db.CertificateChainEntries.Where(x => x.CertificateId == certificate.Id)
            .ExecuteDeleteAsync(cancellationToken);
        foreach (var item in chain.Select((value, position) => (value, position)))
            db.CertificateChainEntries.Add(ToChainEntry(certificate.Id, item.value, item.position));

        var source = await db.KubernetesCertificateSources.FirstOrDefaultAsync(x =>
            x.KubernetesClusterId == cluster.Id && x.Namespace == kubernetesNamespace &&
            x.SecretName == secretName && x.CertificateId == certificate.Id, cancellationToken);
        if (source is null)
            db.KubernetesCertificateSources.Add(new KubernetesCertificateSource
            {
                KubernetesClusterId = cluster.Id,
                CertificateId = certificate.Id,
                Namespace = kubernetesNamespace,
                SecretName = secretName
            });
        else
            source.LastSeenAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
    }

    private static void ApplyCertificate(
        Certificate target, X509Certificate2 source, KubernetesCluster cluster, string ns, string secret)
    {
        target.SerialNumber = source.SerialNumber;
        target.Subject = source.Subject;
        target.CommonName = source.GetNameInfo(X509NameType.SimpleName, false);
        target.Issuer = source.Issuer;
        target.NotBeforeUtc = source.NotBefore.ToUniversalTime();
        target.NotAfterUtc = source.NotAfter.ToUniversalTime();
        target.SignatureAlgorithm = source.SignatureAlgorithm.FriendlyName;
        target.PublicKeyAlgorithm = source.PublicKey.Oid.FriendlyName;
        target.PublicKeySize = KeySize(source);
        target.Version = source.Version;
        target.IsSelfSigned = source.Subject == source.Issuer;
        target.Source = CertificateSource.KubernetesSecret;
        target.SourceName = cluster.Name;
        target.ExternalReference = $"kubernetes://{cluster.Name}/{ns}/{secret}";
        target.PemEncodedCertificate = source.ExportCertificatePem();
        target.LastSeenAtUtc = DateTime.UtcNow;
    }

    private static CertificateChainEntry ToChainEntry(Guid certificateId, X509Certificate2 source, int position) =>
        new()
        {
            CertificateId = certificateId,
            Position = position,
            FingerprintSha256 = Fingerprint(source),
            SerialNumber = source.SerialNumber,
            Subject = source.Subject,
            CommonName = source.GetNameInfo(X509NameType.SimpleName, false),
            Issuer = source.Issuer,
            NotBeforeUtc = source.NotBefore.ToUniversalTime(),
            NotAfterUtc = source.NotAfter.ToUniversalTime(),
            SignatureAlgorithm = source.SignatureAlgorithm.FriendlyName,
            PublicKeyAlgorithm = source.PublicKey.Oid.FriendlyName,
            PublicKeySize = KeySize(source),
            Version = source.Version,
            IsSelfSigned = source.Subject == source.Issuer,
            PemEncodedCertificate = source.ExportCertificatePem(),
            LastSeenAtUtc = DateTime.UtcNow
        };

    private static IEnumerable<(string Name, CertificateSanType Type)> SubjectAlternativeNames(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        if (extension is null) yield break;
        foreach (var dns in extension.EnumerateDnsNames()) yield return (dns, CertificateSanType.DNS);
        foreach (var ip in extension.EnumerateIPAddresses()) yield return (ip.ToString(), CertificateSanType.IP);
    }

    private static List<X509Certificate2> ParsePemCertificates(string pem)
    {
        var result = new List<X509Certificate2>();
        const string begin = "-----BEGIN CERTIFICATE-----";
        const string end = "-----END CERTIFICATE-----";
        var offset = 0;
        while (true)
        {
            var start = pem.IndexOf(begin, offset, StringComparison.Ordinal);
            if (start < 0) break;
            var finish = pem.IndexOf(end, start, StringComparison.Ordinal);
            if (finish < 0) throw new CryptographicException("tls.crt contains an incomplete PEM certificate.");
            finish += end.Length;
            result.Add(X509Certificate2.CreateFromPem(pem.AsSpan(start, finish - start)));
            offset = finish;
        }
        return result;
    }

    private static IEnumerable<string> SecretListPaths(string? namespaces)
    {
        if (string.IsNullOrWhiteSpace(namespaces)) return ["/api/v1/secrets"];
        return namespaces.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(x => $"/api/v1/namespaces/{Uri.EscapeDataString(x)}/secrets");
    }

    private static string? NormalizeNamespaces(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : string.Join(",",
            value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Distinct(StringComparer.OrdinalIgnoreCase));
    private static string? Normalize(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    private static string Fingerprint(X509Certificate2 certificate) =>
        Convert.ToHexString(SHA256.HashData(certificate.RawData));
    private static int? KeySize(X509Certificate2 certificate) =>
        certificate.GetRSAPublicKey()?.KeySize ?? certificate.GetECDsaPublicKey()?.KeySize ?? certificate.GetDSAPublicKey()?.KeySize;
    private static string SafeError(Exception exception) =>
        exception is HttpRequestException ? "Kubernetes API connection failed." : exception.Message[..Math.Min(exception.Message.Length, 2048)];

    private static void Validate(KubernetesClusterUpsertRequest request, bool tokenRequired)
    {
        if (string.IsNullOrWhiteSpace(request.Name)) throw new ArgumentException("Cluster name is required.");
        if (!Uri.TryCreate(request.ApiServer?.Trim(), UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            throw new ArgumentException("Kubernetes API server must be an absolute HTTPS URL.");
        if (tokenRequired && string.IsNullOrWhiteSpace(request.BearerToken))
            throw new ArgumentException("A Kubernetes bearer token is required.");
        foreach (var ns in NormalizeNamespaces(request.Namespaces)?.Split(',') ?? [])
            if (ns.Length > 253 || !char.IsAsciiLetterOrDigit(ns[0]) || !char.IsAsciiLetterOrDigit(ns[^1]) ||
                ns.Any(x => !(char.IsAsciiLetterOrDigit(x) || x is '-' or '.')))
                throw new ArgumentException($"Kubernetes namespace '{ns}' is invalid.");
    }

    private static KubernetesClusterDto ToDto(KubernetesCluster value) =>
        new(value.Id, value.Name, value.ApiServer, value.Description, value.Namespaces,
            !string.IsNullOrWhiteSpace(value.BearerTokenSecretReference), value.IsEnabled,
            value.CreatedAtUtc, value.UpdatedAtUtc, value.LastSyncAtUtc, value.LastSyncStatus, value.LastSyncError);

    private sealed record KubernetesSecretList(
        [property: JsonPropertyName("items")] List<KubernetesSecret> Items,
        [property: JsonPropertyName("metadata")] KubernetesListMetadata? Metadata);
    private sealed record KubernetesListMetadata(
        [property: JsonPropertyName("continue")] string? Continue);
    private sealed record KubernetesSecret(
        [property: JsonPropertyName("metadata")] KubernetesMetadata Metadata,
        [property: JsonPropertyName("type")] string Type,
        [property: JsonPropertyName("data")] Dictionary<string, string>? Data);
    private sealed record KubernetesMetadata(
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("namespace")] string Namespace);
}
