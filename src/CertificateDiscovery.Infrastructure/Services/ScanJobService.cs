namespace CertificateDiscovery.Infrastructure.Services;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

public sealed class ScanJobService(CertificateDiscoveryDbContext db, ILogger<ScanJobService> logger, WorkerService? workers = null)
{
    public async Task<List<ScanJobDto>> ListAsync(CancellationToken cancellationToken)
    {
        var jobs = await db.ScanJobs.OrderByDescending(x => x.RequestedAtUtc).Take(100).ToListAsync(cancellationToken);
        return jobs.Select(ToDto).ToList();
    }

    public async Task<ScanJob?> GetEntityAsync(Guid id, CancellationToken cancellationToken) =>
        await db.ScanJobs.Include(x => x.Results).ThenInclude(x => x.Asset).FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

    public async Task<ScanJobDto?> GetAsync(Guid id, CancellationToken cancellationToken)
    {
        var job = await GetEntityAsync(id, cancellationToken);
        return job is null ? null : ToDto(job);
    }

    public async Task<ScanJob> CreateAsync(IEnumerable<Guid> assetIds, ScanTriggerType triggerType, CancellationToken cancellationToken)
    {
        var distinctIds = assetIds.Distinct().ToList();
        var assets = await db.Assets.Where(x => distinctIds.Contains(x.Id) && x.IsEnabled).ToListAsync(cancellationToken);
        if (assets.Count == 0) throw new InvalidOperationException("No enabled assets were selected.");

        var job = new ScanJob { TriggerType = triggerType, TotalAssetCount = assets.Count };
        foreach (var asset in assets) job.Assets.Add(new ScanJobAsset { ScanJob = job, AssetId = asset.Id });
        db.ScanJobs.Add(job);
        await db.SaveChangesAsync(cancellationToken);
        return job;
    }

    public async Task<ScanJob?> CreateForAssetAsync(Guid assetId, ScanTriggerType triggerType, CancellationToken cancellationToken)
    {
        var asset = await db.Assets.FirstOrDefaultAsync(x => x.Id == assetId && x.IsEnabled, cancellationToken);
        if (asset is null) return null;
        return await CreateAsync([assetId], triggerType, cancellationToken);
    }

    public async Task<WorkerJobDto?> ClaimNextAsync(string workerName, CancellationToken cancellationToken)
    {
        if (workers is not null && !await workers.IsEnabledForClaimsAsync(workerName, cancellationToken))
        {
            logger.LogInformation("Worker {WorkerName} is disabled and cannot claim scan jobs.", workerName);
            return null;
        }

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var job = await db.ScanJobs
            .Include(x => x.Assets).ThenInclude(x => x.Asset)
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

        var assets = job.Assets.Select(x => x.Asset)
            .Where(x => x.IsEnabled)
            .Select(x => new WorkerAssetDto(x.Id, x.Name, x.Host, x.Port, x.Protocol, x.SniHost, x.TimeoutSeconds))
            .ToList();
        return new WorkerJobDto(job.Id, assets);
    }

    public async Task RecordResultAsync(WorkerScanResultRequest request, CancellationToken cancellationToken)
    {
        var asset = await db.Assets.FirstAsync(x => x.Id == request.AssetId, cancellationToken);
        Guid? certificateId = null;
        if (request.Certificate is not null && request.Status == ScanResultStatus.Success)
        {
            var certificate = await UpsertCertificateAsync(request.Certificate, cancellationToken);
            certificateId = certificate.Id;
            await LinkAssetCertificateAsync(asset.Id, certificate.Id, cancellationToken);
        }

        db.ScanResults.Add(new ScanResult
        {
            ScanJobId = request.ScanJobId,
            AssetId = request.AssetId,
            Status = request.Status,
            StartedAtUtc = request.StartedAtUtc,
            CompletedAtUtc = request.CompletedAtUtc,
            DurationMilliseconds = request.DurationMilliseconds,
            ResolvedIpAddress = request.ResolvedIpAddress,
            TlsProtocol = request.TlsProtocol,
            CipherSuite = request.CipherSuite,
            CertificateId = certificateId,
            ErrorType = request.ErrorType,
            ErrorMessage = request.ErrorMessage,
            RawDiagnosticData = request.RawDiagnosticData
        });

        asset.LastScanAtUtc = request.CompletedAtUtc;
        asset.NextScanAtUtc = request.CompletedAtUtc.AddMinutes(asset.ScanIntervalMinutes);
        await db.SaveChangesAsync(cancellationToken);
        logger.LogInformation("Recorded scan result for asset {AssetId} in job {ScanJobId} with status {ResultStatus}", request.AssetId, request.ScanJobId, request.Status);
    }

    public async Task CompleteAsync(Guid jobId, string workerName, CancellationToken cancellationToken)
    {
        var job = await db.ScanJobs.Include(x => x.Results).FirstOrDefaultAsync(x => x.Id == jobId, cancellationToken);
        if (job is null) return;
        var success = job.Results.Count(x => x.Status == ScanResultStatus.Success);
        var failed = job.Results.Count(x => x.Status == ScanResultStatus.Failed);
        job.SuccessfulAssetCount = success;
        job.FailedAssetCount = failed;
        job.CompletedAtUtc = DateTime.UtcNow;
        job.WorkerId = workerName;
        job.Status = failed == 0 ? ScanJobStatus.Completed : success == 0 ? ScanJobStatus.Failed : ScanJobStatus.PartiallyCompleted;
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task FailAsync(Guid jobId, string workerName, string errorMessage, CancellationToken cancellationToken)
    {
        var job = await db.ScanJobs.FindAsync([jobId], cancellationToken);
        if (job is null) return;
        job.Status = ScanJobStatus.Failed;
        job.WorkerId = workerName;
        job.ErrorMessage = errorMessage;
        job.CompletedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<ScanJob?> RequeueAsync(Guid jobId, string requestedBy, CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var job = await db.ScanJobs
            .Include(x => x.Assets)
            .FirstOrDefaultAsync(x => x.Id == jobId, cancellationToken);
        if (job is null) return null;

        var assetIds = job.Assets.Select(x => x.AssetId).Distinct().ToList();
        if (assetIds.Count == 0) return null;

        if (job.Status is ScanJobStatus.Running or ScanJobStatus.Pending)
        {
            job.Status = ScanJobStatus.Failed;
            job.CompletedAtUtc = DateTime.UtcNow;
            job.ErrorMessage = $"Re-queued manually by {requestedBy}.";
        }

        var retryJob = new ScanJob
        {
            Status = ScanJobStatus.Pending,
            TriggerType = ScanTriggerType.Retry,
            RequestedAtUtc = DateTime.UtcNow,
            TotalAssetCount = assetIds.Count
        };

        foreach (var assetId in assetIds)
        {
            retryJob.Assets.Add(new ScanJobAsset { ScanJob = retryJob, AssetId = assetId });
        }

        db.ScanJobs.Add(retryJob);
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return retryJob;
    }

    private async Task<Certificate> UpsertCertificateAsync(WorkerCertificateDto dto, CancellationToken cancellationToken)
    {
        var certificate = await db.Certificates
            .FirstOrDefaultAsync(x => x.FingerprintSha256 == dto.FingerprintSha256, cancellationToken);

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
        certificate.Source = CertificateSource.Scan;
        certificate.SourceName = "Asset Scan";
        certificate.ExternalReference = null;
        certificate.PemEncodedCertificate = dto.PemEncodedCertificate;
        certificate.LastSeenAtUtc = DateTime.UtcNow;

        if (!isNew)
        {
            await db.CertificateSubjectAlternativeNames
                .Where(x => x.CertificateId == certificate.Id)
                .ExecuteDeleteAsync(cancellationToken);
            foreach (var entry in db.ChangeTracker.Entries<CertificateSubjectAlternativeName>()
                         .Where(x => x.Entity.CertificateId == certificate.Id)
                         .ToList())
            {
                entry.State = EntityState.Detached;
            }
            certificate.SubjectAlternativeNames.Clear();
        }

        foreach (var san in dto.SubjectAlternativeNames.DistinctBy(x => new { x.Name, x.Type }))
        {
            db.CertificateSubjectAlternativeNames.Add(new CertificateSubjectAlternativeName
            {
                CertificateId = certificate.Id,
                Name = san.Name,
                Type = san.Type
            });
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

    private async Task LinkAssetCertificateAsync(Guid assetId, Guid certificateId, CancellationToken cancellationToken)
    {
        var active = await db.AssetCertificates.Where(x => x.AssetId == assetId && x.IsCurrentlyActive).ToListAsync(cancellationToken);
        foreach (var relation in active.Where(x => x.CertificateId != certificateId))
        {
            relation.IsCurrentlyActive = false;
            relation.UpdatedAtUtc = DateTime.UtcNow;
        }

        var current = active.FirstOrDefault(x => x.CertificateId == certificateId)
            ?? await db.AssetCertificates.FirstOrDefaultAsync(x => x.AssetId == assetId && x.CertificateId == certificateId, cancellationToken);

        if (current is null)
        {
            db.AssetCertificates.Add(new AssetCertificate { AssetId = assetId, CertificateId = certificateId, FirstSeenAtUtc = DateTime.UtcNow, LastSeenAtUtc = DateTime.UtcNow, IsCurrentlyActive = true });
        }
        else
        {
            current.IsCurrentlyActive = true;
            current.LastSeenAtUtc = DateTime.UtcNow;
            current.UpdatedAtUtc = DateTime.UtcNow;
        }
    }

    private static ScanJobDto ToDto(ScanJob job)
    {
        long? duration = job.StartedAtUtc is not null && job.CompletedAtUtc is not null
            ? (long)(job.CompletedAtUtc.Value - job.StartedAtUtc.Value).TotalMilliseconds
            : null;
        return new ScanJobDto(job.Id, job.Status, job.TriggerType, job.RequestedAtUtc, job.StartedAtUtc, job.CompletedAtUtc, job.TotalAssetCount, job.SuccessfulAssetCount, job.FailedAssetCount, job.WorkerId, job.ErrorMessage, duration);
    }
}
