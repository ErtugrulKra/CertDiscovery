namespace CertificateDiscovery.UnitTests;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

public sealed class ScanJobServiceTests
{
    [Fact]
    public async Task RecordResultAsync_DeactivatesPreviousActiveCertificate()
    {
        await using var db = CreateDb();
        var asset = new Asset { Name = "Test", Host = "example.com", Port = 443 };
        var job = new ScanJob { TotalAssetCount = 1 };
        job.Assets.Add(new ScanJobAsset { ScanJob = job, Asset = asset });
        db.AddRange(asset, job);
        await db.SaveChangesAsync();
        var service = new ScanJobService(db, NullLogger<ScanJobService>.Instance);

        await service.RecordResultAsync(Result(job.Id, asset.Id, "AAAA", "one.test"), CancellationToken.None);
        await service.RecordResultAsync(Result(job.Id, asset.Id, "BBBB", "two.test"), CancellationToken.None);

        var relations = await db.AssetCertificates.OrderBy(x => x.CreatedAtUtc).ToListAsync();
        Assert.Equal(2, relations.Count);
        Assert.False(relations[0].IsCurrentlyActive);
        Assert.True(relations[1].IsCurrentlyActive);
    }

    [Fact]
    public async Task RequeueAsync_ClosesRunningJobAndCreatesPendingRetryJob()
    {
        await using var db = CreateDb();
        var asset = new Asset { Name = "Test", Host = "example.com", Port = 443 };
        var running = new ScanJob
        {
            Status = ScanJobStatus.Running,
            TriggerType = ScanTriggerType.Manual,
            StartedAtUtc = DateTime.UtcNow.AddMinutes(-30),
            TotalAssetCount = 1,
            WorkerId = "worker-1"
        };
        running.Assets.Add(new ScanJobAsset { ScanJob = running, Asset = asset });
        db.AddRange(asset, running);
        await db.SaveChangesAsync();
        var service = new ScanJobService(db, NullLogger<ScanJobService>.Instance);

        var retry = await service.RequeueAsync(running.Id, "test", CancellationToken.None);

        Assert.NotNull(retry);
        var original = await db.ScanJobs.FindAsync(running.Id);
        Assert.Equal(ScanJobStatus.Failed, original!.Status);
        Assert.NotNull(original.CompletedAtUtc);
        Assert.Contains("Re-queued manually", original.ErrorMessage);
        Assert.Equal(ScanJobStatus.Pending, retry!.Status);
        Assert.Equal(ScanTriggerType.Retry, retry.TriggerType);
        Assert.Equal(1, await db.ScanJobAssets.CountAsync(x => x.ScanJobId == retry.Id));
    }

    [Fact]
    public async Task RecordResultAsync_AcceptsFailedResultWithoutCertificate()
    {
        await using var db = CreateDb();
        var asset = new Asset { Name = "Invalid", Host = "invalid.local", Port = 443 };
        var job = new ScanJob { Status = ScanJobStatus.Running, TotalAssetCount = 1 };
        job.Assets.Add(new ScanJobAsset { ScanJob = job, Asset = asset });
        db.AddRange(asset, job);
        await db.SaveChangesAsync();
        var service = new ScanJobService(db, NullLogger<ScanJobService>.Instance);
        var request = new WorkerScanResultRequest(
            job.Id,
            asset.Id,
            ScanResultStatus.Failed,
            DateTime.UtcNow.AddMilliseconds(-50),
            DateTime.UtcNow,
            50,
            null,
            null,
            null,
            null,
            ScanErrorType.DnsResolutionFailed,
            "Name or service not known",
            "DnsResolutionError");

        await service.RecordResultAsync(request, CancellationToken.None);

        var result = await db.ScanResults.SingleAsync();
        Assert.Equal(ScanResultStatus.Failed, result.Status);
        Assert.Equal(ScanErrorType.DnsResolutionFailed, result.ErrorType);
        Assert.Null(result.CertificateId);
    }

    [Fact]
    public async Task RecordResultAsync_UpdatesExistingCertificateSansWithoutConcurrencyError()
    {
        await using var db = CreateDb();
        var asset = new Asset { Name = "Test", Host = "example.com", Port = 443 };
        var job = new ScanJob { Status = ScanJobStatus.Running, TotalAssetCount = 1 };
        job.Assets.Add(new ScanJobAsset { ScanJob = job, Asset = asset });
        db.AddRange(asset, job);
        await db.SaveChangesAsync();
        var service = new ScanJobService(db, NullLogger<ScanJobService>.Instance);

        await service.RecordResultAsync(Result(job.Id, asset.Id, "SAME", "one.test"), CancellationToken.None);
        await service.RecordResultAsync(Result(job.Id, asset.Id, "SAME", "two.test"), CancellationToken.None);

        var certificate = await db.Certificates.Include(x => x.SubjectAlternativeNames).SingleAsync();
        Assert.Equal("two.test", certificate.CommonName);
        Assert.Single(certificate.SubjectAlternativeNames);
        Assert.Equal("two.test", certificate.SubjectAlternativeNames.Single().Name);
    }

    private static WorkerScanResultRequest Result(Guid jobId, Guid assetId, string fingerprint, string commonName) =>
        new(
            jobId,
            assetId,
            ScanResultStatus.Success,
            DateTime.UtcNow.AddSeconds(-1),
            DateTime.UtcNow,
            100,
            "127.0.0.1",
            "TLSv1.3",
            "TLS_AES_256_GCM_SHA384",
            new WorkerCertificateDto(
                fingerprint,
                "01",
                $"CN={commonName}",
                commonName,
                $"CN={commonName}",
                DateTime.UtcNow.AddDays(-1),
                DateTime.UtcNow.AddDays(90),
                "sha256",
                "RSA",
                2048,
                3,
                true,
                "-----BEGIN CERTIFICATE-----",
                [new SubjectAlternativeNameDto(commonName, CertificateSanType.DNS)]),
            ScanErrorType.None,
            null,
            null);

    private static CertificateDiscoveryDbContext CreateDb()
    {
        var options = new DbContextOptionsBuilder<CertificateDiscoveryDbContext>()
            .UseSqlite("Data Source=:memory:")
            .Options;
        var db = new CertificateDiscoveryDbContext(options);
        db.Database.OpenConnection();
        db.Database.EnsureCreated();
        return db;
    }
}
