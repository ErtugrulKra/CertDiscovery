namespace CertificateDiscovery.Infrastructure.Services;

using System.Diagnostics;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

public sealed class VaultDiscoveryService(CertificateDiscoveryDbContext db, IHttpClientFactory httpClientFactory)
{
    public async Task<List<VaultDiscoveryJobDto>> ListAsync(CancellationToken cancellationToken)
    {
        var jobs = await db.VaultDiscoveryJobs.Include(x => x.VaultServer).OrderByDescending(x => x.RequestedAtUtc).Take(100).ToListAsync(cancellationToken);
        return jobs.Select(ToDto).ToList();
    }

    public async Task<VaultDiscoveryCreateOptionsDto> GetCreateOptionsAsync(CancellationToken cancellationToken) =>
        new(await db.VaultServers.AsNoTracking().Where(x => x.IsEnabled).OrderBy(x => x.Name).Select(x => ToDto(x)).ToListAsync(cancellationToken));

    public async Task<VaultDiscoveryJob?> GetEntityAsync(Guid id, CancellationToken cancellationToken) =>
        await db.VaultDiscoveryJobs
            .Include(x => x.VaultServer)
            .Include(x => x.Results.OrderByDescending(r => r.CompletedAtUtc))
            .ThenInclude(x => x.Certificate)
            .Include(x => x.Results)
            .ThenInclude(x => x.PromotedAsset)
            .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

    public async Task<VaultDiscoveryJob> CreateAsync(VaultDiscoveryJobCreateRequest request, string requestedBy, CancellationToken cancellationToken)
    {
        Validate(request);
        var vault = await db.VaultServers.FirstOrDefaultAsync(x => x.Id == request.VaultServerId && x.IsEnabled, cancellationToken)
            ?? throw new InvalidOperationException("Enabled Vault server was not found.");

        var job = new VaultDiscoveryJob
        {
            Name = string.IsNullOrWhiteSpace(request.Name) ? $"Vault discovery {request.BasePath}" : request.Name.Trim(),
            VaultServerId = vault.Id,
            KvMountPath = NormalizePath(request.KvMountPath),
            BasePath = NormalizePath(request.BasePath),
            Recursive = request.Recursive,
            CreateAssets = request.CreateAssets,
            RequestedBy = requestedBy,
            Status = ScanJobStatus.Pending
        };
        db.VaultDiscoveryJobs.Add(job);
        await db.SaveChangesAsync(cancellationToken);
        return job;
    }

    public async Task RunAsync(Guid id, CancellationToken cancellationToken)
    {
        var job = await db.VaultDiscoveryJobs.Include(x => x.VaultServer).Include(x => x.Results).FirstOrDefaultAsync(x => x.Id == id, cancellationToken)
            ?? throw new InvalidOperationException("Vault discovery job was not found.");
        if (job.Status == ScanJobStatus.Running) throw new InvalidOperationException("Vault discovery job is already running.");
        if (string.IsNullOrWhiteSpace(job.VaultServer.Token)) throw new InvalidOperationException("Vault token is required for Vault Discovery.");

        job.Status = ScanJobStatus.Running;
        job.StartedAtUtc = DateTime.UtcNow;
        job.CompletedAtUtc = null;
        job.ErrorMessage = null;
        job.SecretCount = 0;
        job.CertificateFoundCount = 0;
        job.AssetCreatedCount = 0;
        job.FailedSecretCount = 0;
        db.VaultDiscoveryResults.RemoveRange(job.Results);
        await db.SaveChangesAsync(cancellationToken);

        try
        {
            var client = CreateVaultClient(job.VaultServer);
            var secrets = await ListSecretsAsync(client, job.KvMountPath, job.BasePath, job.Recursive, cancellationToken);
            job.SecretCount = secrets.Count;
            await db.SaveChangesAsync(cancellationToken);

            foreach (var secretPath in secrets)
            {
                var started = DateTime.UtcNow;
                var stopwatch = Stopwatch.StartNew();
                var result = new VaultDiscoveryResult { VaultDiscoveryJobId = job.Id, SecretPath = $"{job.KvMountPath}/{secretPath}", StartedAtUtc = started };
                db.VaultDiscoveryResults.Add(result);
                try
                {
                    var secret = await ReadSecretAsync(client, job.KvMountPath, secretPath, cancellationToken);
                    var certificatePem = TryGetString(secret, "certificate_pem") ?? TryGetString(secret, "cert_pem") ?? TryGetString(secret, "certificate");
                    var fullChainPem = TryGetString(secret, "fullchain_pem") ?? TryGetString(secret, "chain_pem") ?? certificatePem;
                    if (string.IsNullOrWhiteSpace(certificatePem)) throw new InvalidOperationException("Secret does not contain certificate_pem, cert_pem, or certificate.");

                    var certificate = await UpsertCertificateAsync(certificatePem, fullChainPem, job.VaultServer.Name, $"{job.KvMountPath}/{secretPath}", cancellationToken);
                    result.CertificateId = certificate.Id;
                    result.Domain = TryGetString(secret, "domain") ?? certificate.CommonName;
                    result.SubjectAlternativeNames = TryGetSansText(secret, certificate);
                    result.Status = ScanResultStatus.Success;
                    job.CertificateFoundCount++;

                    if (job.CreateAssets)
                    {
                        var created = await CreateAssetsAsync(certificate, result.Domain, result.SubjectAlternativeNames, cancellationToken);
                        job.AssetCreatedCount += created;
                        result.PromotedAssetId = await FindPrimaryAssetIdAsync(result.Domain, cancellationToken);
                    }
                }
                catch (Exception ex)
                {
                    result.Status = ScanResultStatus.Failed;
                    result.ErrorMessage = ex.Message;
                    job.FailedSecretCount++;
                }
                finally
                {
                    stopwatch.Stop();
                    result.CompletedAtUtc = DateTime.UtcNow;
                    result.DurationMilliseconds = stopwatch.ElapsedMilliseconds;
                    await db.SaveChangesAsync(cancellationToken);
                }
            }

            job.Status = job.FailedSecretCount > 0 && job.CertificateFoundCount > 0 ? ScanJobStatus.PartiallyCompleted : job.FailedSecretCount > 0 ? ScanJobStatus.Failed : ScanJobStatus.Completed;
            job.CompletedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            job.Status = ScanJobStatus.Failed;
            job.ErrorMessage = ex.Message;
            job.CompletedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
            throw;
        }
    }

    private HttpClient CreateVaultClient(VaultServer server)
    {
        var client = httpClientFactory.CreateClient();
        client.BaseAddress = server.BaseUrl;
        client.DefaultRequestHeaders.Add("X-Vault-Token", server.Token);
        return client;
    }

    private static async Task<List<string>> ListSecretsAsync(HttpClient client, string mount, string basePath, bool recursive, CancellationToken cancellationToken)
    {
        var found = new List<string>();
        await ListIntoAsync(client, mount, basePath.Trim('/'), recursive, found, cancellationToken);
        return found.Where(x => !x.EndsWith("/", StringComparison.Ordinal)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static async Task ListIntoAsync(HttpClient client, string mount, string path, bool recursive, List<string> found, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"/v1/{mount}/metadata/{path}?list=true");
        using var response = await client.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            found.Add(path);
            return;
        }

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        if (!document.RootElement.TryGetProperty("data", out var data) || !data.TryGetProperty("keys", out var keys) || keys.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var keyElement in keys.EnumerateArray())
        {
            var key = keyElement.GetString();
            if (string.IsNullOrWhiteSpace(key)) continue;
            var child = $"{path.TrimEnd('/')}/{key.TrimEnd('/')}";
            if (key.EndsWith("/", StringComparison.Ordinal))
            {
                if (recursive) await ListIntoAsync(client, mount, child, true, found, cancellationToken);
            }
            else
            {
                found.Add(child);
            }
        }
    }

    private static async Task<JsonElement> ReadSecretAsync(HttpClient client, string mount, string path, CancellationToken cancellationToken)
    {
        using var response = await client.GetAsync($"/v1/{mount}/data/{path}", cancellationToken);
        response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        return document.RootElement.GetProperty("data").GetProperty("data").Clone();
    }

    private async Task<Certificate> UpsertCertificateAsync(string certificatePem, string? fullChainPem, string sourceName, string externalReference, CancellationToken cancellationToken)
    {
        var leaf = X509Certificate2.CreateFromPem(certificatePem);
        var chain = ParsePemCertificates(string.IsNullOrWhiteSpace(fullChainPem) ? certificatePem : fullChainPem);
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
        certificate.Source = CertificateSource.VaultKv;
        certificate.SourceName = sourceName;
        certificate.ExternalReference = externalReference;
        certificate.PemEncodedCertificate = certificatePem;
        certificate.LastSeenAtUtc = DateTime.UtcNow;

        await db.CertificateSubjectAlternativeNames.Where(x => x.CertificateId == certificate.Id).ExecuteDeleteAsync(cancellationToken);
        foreach (var san in ExtractSans(leaf).DistinctBy(x => new { x.Name, x.Type }))
        {
            db.CertificateSubjectAlternativeNames.Add(new CertificateSubjectAlternativeName { CertificateId = certificate.Id, Name = san.Name, Type = san.Type });
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
                PemEncodedCertificate = PemEncode(entry.cert),
                LastSeenAtUtc = DateTime.UtcNow
            });
        }

        await db.SaveChangesAsync(cancellationToken);
        return certificate;
    }

    private async Task<int> CreateAssetsAsync(Certificate certificate, string? domain, string? sansText, CancellationToken cancellationToken)
    {
        var names = new List<string>();
        if (!string.IsNullOrWhiteSpace(domain)) names.Add(domain);
        if (!string.IsNullOrWhiteSpace(sansText)) names.AddRange(sansText.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        names.AddRange(certificate.SubjectAlternativeNames.Where(x => x.Type == CertificateSanType.DNS).Select(x => x.Name));
        names = names.Select(NormalizeHost).Where(x => !string.IsNullOrWhiteSpace(x) && !x.StartsWith("*.", StringComparison.Ordinal)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        var created = 0;
        foreach (var host in names)
        {
            var asset = await db.Assets.FirstOrDefaultAsync(x => x.Host == host && x.Port == 443 && x.Protocol == AssetProtocol.HTTPS, cancellationToken);
            if (asset is null)
            {
                asset = new Asset
                {
                    Name = host,
                    Host = host,
                    Port = 443,
                    Protocol = AssetProtocol.HTTPS,
                    SniHost = host,
                    Environment = AssetEnvironment.Other,
                    AssetType = AssetType.WebApplication,
                    Owner = "Vault Discovery",
                    IsEnabled = true,
                    ScanIntervalMinutes = 1440,
                    TimeoutSeconds = 10,
                    NextScanAtUtc = DateTime.UtcNow
                };
                db.Assets.Add(asset);
                created++;
            }

            var link = await db.AssetCertificates.FirstOrDefaultAsync(x => x.AssetId == asset.Id && x.CertificateId == certificate.Id, cancellationToken);
            if (link is null)
            {
                db.AssetCertificates.Add(new AssetCertificate { AssetId = asset.Id, CertificateId = certificate.Id, FirstSeenAtUtc = DateTime.UtcNow, LastSeenAtUtc = DateTime.UtcNow, IsCurrentlyActive = true });
            }
            else
            {
                link.LastSeenAtUtc = DateTime.UtcNow;
                link.IsCurrentlyActive = true;
            }
        }

        await db.SaveChangesAsync(cancellationToken);
        return created;
    }

    private async Task<Guid?> FindPrimaryAssetIdAsync(string? domain, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(domain)) return null;
        var host = NormalizeHost(domain);
        return await db.Assets.Where(x => x.Host == host && x.Port == 443 && x.Protocol == AssetProtocol.HTTPS).Select(x => (Guid?)x.Id).FirstOrDefaultAsync(cancellationToken);
    }

    private static string? TryGetString(JsonElement data, string name)
    {
        if (!data.TryGetProperty(name, out var value)) return null;
        return value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString();
    }

    private static string? TryGetSansText(JsonElement data, Certificate certificate)
    {
        if (data.TryGetProperty("sans", out var sans) && sans.ValueKind == JsonValueKind.Array)
        {
            return string.Join(", ", sans.EnumerateArray().Select(x => x.GetString()).Where(x => !string.IsNullOrWhiteSpace(x)));
        }

        return string.Join(", ", certificate.SubjectAlternativeNames.Where(x => x.Type == CertificateSanType.DNS).Select(x => x.Name));
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

    private static IReadOnlyList<CertificateSubjectAlternativeName> ExtractSans(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        if (extension is null) return [];
        var values = new List<CertificateSubjectAlternativeName>();
        foreach (var dns in extension.EnumerateDnsNames()) values.Add(new CertificateSubjectAlternativeName { Name = dns, Type = CertificateSanType.DNS });
        foreach (var ip in extension.EnumerateIPAddresses()) values.Add(new CertificateSubjectAlternativeName { Name = ip.ToString(), Type = CertificateSanType.IP });
        return values;
    }

    private static void Validate(VaultDiscoveryJobCreateRequest request)
    {
        if (request.VaultServerId == Guid.Empty) throw new ArgumentException("Vault server is required.");
        if (string.IsNullOrWhiteSpace(request.KvMountPath)) throw new ArgumentException("KV mount path is required.");
        if (string.IsNullOrWhiteSpace(request.BasePath)) throw new ArgumentException("Base path is required.");
    }

    private static string NormalizePath(string value) => value.Trim().Trim('/');
    private static string NormalizeHost(string value) => value.Trim().TrimEnd('.').ToLowerInvariant();
    private static string Fingerprint(X509Certificate2 certificate) => Convert.ToHexString(SHA256.HashData(certificate.RawData));
    private static string PemEncode(X509Certificate2 certificate) => "-----BEGIN CERTIFICATE-----\n" + Convert.ToBase64String(certificate.RawData, Base64FormattingOptions.InsertLineBreaks) + "\n-----END CERTIFICATE-----\n";
    private static int? GetPublicKeySize(X509Certificate2 certificate) => certificate.GetRSAPublicKey()?.KeySize ?? certificate.GetECDsaPublicKey()?.KeySize ?? certificate.GetDSAPublicKey()?.KeySize;

    private static VaultDiscoveryJobDto ToDto(VaultDiscoveryJob job)
    {
        long? duration = job.StartedAtUtc is not null && job.CompletedAtUtc is not null ? (long)(job.CompletedAtUtc.Value - job.StartedAtUtc.Value).TotalMilliseconds : null;
        return new VaultDiscoveryJobDto(job.Id, job.Name, job.VaultServer.Name, job.KvMountPath, job.BasePath, job.Recursive, job.CreateAssets, job.Status, job.RequestedAtUtc, job.StartedAtUtc, job.CompletedAtUtc, job.SecretCount, job.CertificateFoundCount, job.AssetCreatedCount, job.FailedSecretCount, job.RequestedBy, job.ErrorMessage, duration);
    }

    private static VaultServerDto ToDto(VaultServer server) =>
        new(server.Id, server.Name, server.BaseUrl, server.Description, server.PkiMountPath, !string.IsNullOrWhiteSpace(server.Token), server.ScanPublicEndpoint, server.ImportPkiCertificates, server.IsEnabled, server.CreatedAtUtc, server.UpdatedAtUtc, server.LastSyncAtUtc, server.LastSyncStatus, server.LastSyncError);
}
