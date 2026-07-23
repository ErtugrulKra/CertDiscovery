namespace CertificateDiscovery.UnitTests;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Infrastructure.Persistence;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

public sealed class NetworkDiscoveryServiceTests
{
    [Fact]
    public void ParsePorts_UsesDefaultsWhenInputIsEmpty()
    {
        var ports = NetworkDiscoveryService.ParsePorts("");

        Assert.Contains(443, ports);
        Assert.Contains(993, ports);
    }

    [Fact]
    public async Task CreateAsync_RejectsOverlyLargeRange()
    {
        await using var db = CreateDb();
        var service = new NetworkDiscoveryService(db, NullLogger<NetworkDiscoveryService>.Instance);
        var request = new DiscoveryJobCreateRequest("Too large", "10.0.0.0/8", "443", 3, 100);

        await Assert.ThrowsAsync<ArgumentException>(() => service.CreateAsync(request, "test", CancellationToken.None));
    }

    [Fact]
    public async Task CreateAsync_CreatesPendingJobWithEndpointCount()
    {
        await using var db = CreateDb();
        var service = new NetworkDiscoveryService(db, NullLogger<NetworkDiscoveryService>.Instance);
        var request = new DiscoveryJobCreateRequest("Small", "10.10.0.0/30", "443,8443", 3, 20);

        var job = await service.CreateAsync(request, "test", CancellationToken.None);

        Assert.Equal("443,8443", job.Ports);
        Assert.Equal(4, job.TotalEndpointCount);
    }

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
