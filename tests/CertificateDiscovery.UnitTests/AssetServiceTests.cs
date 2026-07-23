namespace CertificateDiscovery.UnitTests;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Infrastructure.Persistence;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;

public sealed class AssetServiceTests
{
    [Fact]
    public async Task CreateAsync_RejectsInvalidPort()
    {
        await using var db = CreateDb();
        var service = new AssetService(db);
        var request = new AssetCreateRequest("Bad", "example.com", 70000, AssetProtocol.HTTPS, null, null, null, AssetEnvironment.Test, AssetType.Api, null, true, 60, 10, null);

        await Assert.ThrowsAsync<ArgumentException>(() => service.CreateAsync(request, CancellationToken.None));
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
