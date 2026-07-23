namespace CertificateDiscovery.Infrastructure.Services;

using System.Net;
using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

public sealed class NetworkDiscoveryService(CertificateDiscoveryDbContext db, ILogger<NetworkDiscoveryService> logger, WorkerService? workers = null)
{
    private static readonly int[] DefaultPorts = [443, 8443, 9443, 465, 993, 995, 636];

    public async Task<List<DiscoveryJobDto>> ListAsync(CancellationToken cancellationToken)
    {
        var jobs = await db.DiscoveryJobs.OrderByDescending(x => x.RequestedAtUtc).Take(100).ToListAsync(cancellationToken);
        return jobs.Select(ToDto).ToList();
    }

    public async Task<DiscoveryJob?> GetEntityAsync(Guid id, CancellationToken cancellationToken) =>
        await db.DiscoveryJobs
            .Include(x => x.Results.OrderByDescending(r => r.CompletedAtUtc))
            .ThenInclude(x => x.Certificate)
            .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

    public async Task<DiscoveryJob> CreateAsync(DiscoveryJobCreateRequest request, string requestedBy, CancellationToken cancellationToken)
    {
        ValidateCidr(request.Cidr);
        var ports = ParsePorts(request.Ports);
        if (request.TimeoutSeconds is < 1 or > 30) throw new ArgumentException("Timeout must be between 1 and 30 seconds.");
        if (request.MaxConcurrency is < 1 or > 1000) throw new ArgumentException("Concurrency must be between 1 and 1000.");

        var job = new DiscoveryJob
        {
            Name = string.IsNullOrWhiteSpace(request.Name) ? $"Discovery {request.Cidr}" : request.Name.Trim(),
            Cidr = request.Cidr.Trim(),
            Ports = string.Join(",", ports),
            TimeoutSeconds = request.TimeoutSeconds,
            MaxConcurrency = request.MaxConcurrency,
            RequestedBy = requestedBy,
            TotalEndpointCount = CountUsableHosts(request.Cidr) * ports.Count
        };
        db.DiscoveryJobs.Add(job);
        await db.SaveChangesAsync(cancellationToken);
        return job;
    }

    public async Task<WorkerDiscoveryJobDto?> ClaimNextAsync(string workerName, CancellationToken cancellationToken)
    {
        if (workers is not null && !await workers.IsEnabledForClaimsAsync(workerName, cancellationToken))
        {
            logger.LogInformation("Worker {WorkerName} is disabled and cannot claim network discovery jobs.", workerName);
            return null;
        }

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var job = await db.DiscoveryJobs
            .Where(x => x.Status == ScanJobStatus.Pending)
            .OrderBy(x => x.RequestedAtUtc)
            .FirstOrDefaultAsync(cancellationToken);
        if (job is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return null;
        }

        job.Status = ScanJobStatus.Running;
        job.StartedAtUtc = DateTime.UtcNow;
        job.WorkerId = workerName;
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return new WorkerDiscoveryJobDto(job.Id, job.Cidr, ParsePorts(job.Ports), job.TimeoutSeconds, job.MaxConcurrency);
    }

    public async Task RecordResultAsync(WorkerDiscoveryResultRequest request, CancellationToken cancellationToken)
    {
        Guid? certificateId = null;
        if (request.Certificate is not null && request.Status == ScanResultStatus.Success)
        {
            var certificate = await UpsertCertificateAsync(request.Certificate, cancellationToken);
            certificateId = certificate.Id;
        }

        var existing = await db.DiscoveredEndpoints.FirstOrDefaultAsync(x =>
            x.DiscoveryJobId == request.DiscoveryJobId &&
            x.IpAddress == request.IpAddress &&
            x.Port == request.Port,
            cancellationToken);

        var isNewResult = existing is null;
        if (existing is null)
        {
            existing = new DiscoveredEndpoint { DiscoveryJobId = request.DiscoveryJobId, IpAddress = request.IpAddress, Port = request.Port };
            db.DiscoveredEndpoints.Add(existing);
        }

        existing.ProtocolGuess = request.ProtocolGuess;
        existing.Status = request.Status;
        existing.StartedAtUtc = request.StartedAtUtc;
        existing.CompletedAtUtc = request.CompletedAtUtc;
        existing.DurationMilliseconds = request.DurationMilliseconds;
        existing.TlsProtocol = request.TlsProtocol;
        existing.CipherSuite = request.CipherSuite;
        existing.CertificateId = certificateId;
        existing.ReverseDnsName = request.ReverseDnsName;
        existing.ErrorType = request.ErrorType;
        existing.ErrorMessage = request.ErrorMessage;
        existing.RawDiagnosticData = request.RawDiagnosticData;

        var job = await db.DiscoveryJobs.FindAsync([request.DiscoveryJobId], cancellationToken);
        if (job is not null && isNewResult)
        {
            job.ScannedEndpointCount += 1;
            if (certificateId is not null) job.CertificateFoundCount += 1;
            if (request.Status == ScanResultStatus.Failed) job.FailedEndpointCount += 1;
        }

        await db.SaveChangesAsync(cancellationToken);
        logger.LogInformation("Recorded discovery result {DiscoveryJobId} {IpAddress}:{Port} {ResultStatus}", request.DiscoveryJobId, request.IpAddress, request.Port, request.Status);
    }

    public async Task CompleteAsync(Guid id, string workerName, CancellationToken cancellationToken)
    {
        var job = await db.DiscoveryJobs.Include(x => x.Results).FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (job is null) return;
        job.CompletedAtUtc = DateTime.UtcNow;
        job.WorkerId = workerName;
        job.ScannedEndpointCount = job.Results.Count;
        job.CertificateFoundCount = job.Results.Count(x => x.CertificateId != null);
        job.FailedEndpointCount = job.Results.Count(x => x.Status == ScanResultStatus.Failed);
        job.Status = job.CertificateFoundCount > 0 || job.FailedEndpointCount < job.TotalEndpointCount ? ScanJobStatus.Completed : ScanJobStatus.Failed;
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task FailAsync(Guid id, string workerName, string errorMessage, CancellationToken cancellationToken)
    {
        var job = await db.DiscoveryJobs.FindAsync([id], cancellationToken);
        if (job is null) return;
        job.Status = ScanJobStatus.Failed;
        job.WorkerId = workerName;
        job.ErrorMessage = errorMessage;
        job.CompletedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<Asset?> PromoteAsync(Guid endpointId, CancellationToken cancellationToken)
    {
        var endpoint = await db.DiscoveredEndpoints.Include(x => x.Certificate).FirstOrDefaultAsync(x => x.Id == endpointId, cancellationToken);
        if (endpoint is null || endpoint.CertificateId is null) return null;

        var asset = new Asset
        {
            Name = endpoint.ReverseDnsName ?? $"{endpoint.IpAddress}:{endpoint.Port}",
            Host = endpoint.ReverseDnsName ?? endpoint.IpAddress,
            Port = endpoint.Port,
            Protocol = endpoint.ProtocolGuess,
            SniHost = endpoint.ReverseDnsName,
            Environment = AssetEnvironment.Other,
            AssetType = AssetType.Other,
            Owner = "Discovery",
            IsEnabled = true,
            ScanIntervalMinutes = 1440,
            TimeoutSeconds = 10,
            NextScanAtUtc = DateTime.UtcNow
        };
        db.Assets.Add(asset);
        await db.SaveChangesAsync(cancellationToken);

        endpoint.PromotedAssetId = asset.Id;
        db.AssetCertificates.Add(new AssetCertificate
        {
            AssetId = asset.Id,
            CertificateId = endpoint.CertificateId.Value,
            FirstSeenAtUtc = endpoint.CompletedAtUtc,
            LastSeenAtUtc = endpoint.CompletedAtUtc,
            IsCurrentlyActive = true
        });
        await db.SaveChangesAsync(cancellationToken);
        return asset;
    }

    public static IReadOnlyList<int> ParsePorts(string? ports)
    {
        if (string.IsNullOrWhiteSpace(ports)) return DefaultPorts;
        var parsed = ports.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(x => int.TryParse(x, out var port) ? port : -1)
            .Where(x => x is >= 1 and <= 65535)
            .Distinct()
            .Order()
            .ToList();
        return parsed.Count == 0 ? DefaultPorts : parsed;
    }

    private async Task<Certificate> UpsertCertificateAsync(WorkerCertificateDto dto, CancellationToken cancellationToken)
    {
        var certificate = await db.Certificates.FirstOrDefaultAsync(x => x.FingerprintSha256 == dto.FingerprintSha256, cancellationToken);
        var isNew = certificate is null;
        if (certificate is null)
        {
            certificate = new Certificate { FingerprintSha256 = dto.FingerprintSha256, CreatedAtUtc = DateTime.UtcNow };
            db.Certificates.Add(certificate);
        }

        certificate.SerialNumber = dto.SerialNumber;
        certificate.Subject = dto.Subject;
        certificate.CommonName = dto.CommonName;
        certificate.Issuer = dto.Issuer;
        certificate.NotBeforeUtc = dto.NotBeforeUtc;
        certificate.NotAfterUtc = dto.NotAfterUtc;
        certificate.SignatureAlgorithm = dto.SignatureAlgorithm;
        certificate.PublicKeyAlgorithm = dto.PublicKeyAlgorithm;
        certificate.PublicKeySize = dto.PublicKeySize;
        certificate.Version = dto.Version;
        certificate.IsSelfSigned = dto.IsSelfSigned;
        certificate.Source = CertificateSource.NetworkDiscovery;
        certificate.SourceName = "Network Discovery";
        certificate.ExternalReference = null;
        certificate.PemEncodedCertificate = dto.PemEncodedCertificate;
        certificate.LastSeenAtUtc = DateTime.UtcNow;

        if (!isNew)
        {
            await db.CertificateSubjectAlternativeNames.Where(x => x.CertificateId == certificate.Id).ExecuteDeleteAsync(cancellationToken);
        }

        foreach (var san in dto.SubjectAlternativeNames.DistinctBy(x => new { x.Name, x.Type }))
        {
            db.CertificateSubjectAlternativeNames.Add(new CertificateSubjectAlternativeName { CertificateId = certificate.Id, Name = san.Name, Type = san.Type });
        }

        await ReplaceChainEntriesAsync(certificate.Id, dto, cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
        return certificate;
    }

    private async Task ReplaceChainEntriesAsync(Guid certificateId, WorkerCertificateDto dto, CancellationToken cancellationToken)
    {
        await db.CertificateChainEntries.Where(x => x.CertificateId == certificateId).ExecuteDeleteAsync(cancellationToken);

        var entries = dto.ChainEntries is { Count: > 0 }
            ? dto.ChainEntries
            : [new WorkerCertificateChainEntryDto(0, dto.FingerprintSha256, dto.SerialNumber, dto.Subject, dto.CommonName, dto.Issuer, dto.NotBeforeUtc, dto.NotAfterUtc, dto.SignatureAlgorithm, dto.PublicKeyAlgorithm, dto.PublicKeySize, dto.Version, dto.IsSelfSigned, dto.PemEncodedCertificate)];

        foreach (var entry in entries.OrderBy(x => x.Position).DistinctBy(x => x.Position))
        {
            db.CertificateChainEntries.Add(new CertificateChainEntry
            {
                CertificateId = certificateId,
                Position = entry.Position,
                FingerprintSha256 = entry.FingerprintSha256,
                SerialNumber = entry.SerialNumber,
                Subject = entry.Subject,
                CommonName = entry.CommonName,
                Issuer = entry.Issuer,
                NotBeforeUtc = entry.NotBeforeUtc,
                NotAfterUtc = entry.NotAfterUtc,
                SignatureAlgorithm = entry.SignatureAlgorithm,
                PublicKeyAlgorithm = entry.PublicKeyAlgorithm,
                PublicKeySize = entry.PublicKeySize,
                Version = entry.Version,
                IsSelfSigned = entry.IsSelfSigned,
                PemEncodedCertificate = entry.PemEncodedCertificate,
                LastSeenAtUtc = DateTime.UtcNow
            });
        }
    }

    private static void ValidateCidr(string cidr)
    {
        var parts = cidr.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            throw new ArgumentException("CIDR must be a valid IPv4 range like 10.10.0.0/24.");
        }
        if (!int.TryParse(parts[1], out var prefix) || prefix is < 16 or > 32)
        {
            throw new ArgumentException("CIDR prefix must be between /16 and /32 for safety.");
        }
    }

    private static int CountUsableHosts(string cidr)
    {
        var prefix = int.Parse(cidr.Split('/')[1]);
        if (prefix == 32) return 1;
        if (prefix == 31) return 2;
        return Math.Max(0, (int)Math.Pow(2, 32 - prefix) - 2);
    }

    private static DiscoveryJobDto ToDto(DiscoveryJob job)
    {
        long? duration = job.StartedAtUtc is not null && job.CompletedAtUtc is not null
            ? (long)(job.CompletedAtUtc.Value - job.StartedAtUtc.Value).TotalMilliseconds
            : null;
        return new DiscoveryJobDto(job.Id, job.Name, job.Cidr, job.Ports, job.Status, job.RequestedAtUtc, job.StartedAtUtc, job.CompletedAtUtc, job.TotalEndpointCount, job.ScannedEndpointCount, job.CertificateFoundCount, job.FailedEndpointCount, job.TimeoutSeconds, job.MaxConcurrency, job.WorkerId, job.ErrorMessage, job.RequestedBy, duration);
    }
}
