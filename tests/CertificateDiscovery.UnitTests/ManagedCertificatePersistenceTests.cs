using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertificateDiscovery.Application.Inventory;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Inventory;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace CertificateDiscovery.UnitTests;

public sealed class ManagedCertificatePersistenceTests
{
    [Fact]
    public async Task Managed_request_model_has_no_certificate_material_columns()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = CreateDb(connection);

        var entity = db.Model.FindEntityType(typeof(AcmeCertificateRequest))!;
        Assert.DoesNotContain(entity.GetProperties(), property =>
            property.Name.Contains("CertificatePem", StringComparison.OrdinalIgnoreCase) ||
            property.Name.Contains("PrivateKey", StringComparison.OrdinalIgnoreCase) ||
            property.Name.Contains("FullChain", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Managed_inventory_persists_metadata_but_no_leaf_or_chain_pem()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = CreateDb(connection);
        await db.Database.EnsureCreatedAsync();

        using var rsa = RSA.Create(2048);
        var requestBuilder = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=managed.example", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = requestBuilder.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(30));
        var pem = certificate.ExportCertificatePem();
        var request = new AcmeCertificateRequest
        {
            Domain = "managed.example",
            VaultSecretPath = "certificates/managed.example"
        };

        var id = await new CertificateInventoryWriter(db).UpsertAsync(
            new CertificateInventoryContext(request, null, ["managed.example"], pem, pem),
            default);

        db.ChangeTracker.Clear();
        var persisted = await db.Certificates.Include(x => x.ChainEntries).SingleAsync(x => x.Id == id);
        Assert.Equal(CertificateSource.Acme, persisted.Source);
        Assert.Null(persisted.PemEncodedCertificate);
        Assert.NotEmpty(persisted.Subject);
        Assert.NotEmpty(persisted.ChainEntries);
        Assert.All(persisted.ChainEntries, entry => Assert.Null(entry.PemEncodedCertificate));
    }

    private static CertificateDiscoveryDbContext CreateDb(SqliteConnection connection) =>
        new(new DbContextOptionsBuilder<CertificateDiscoveryDbContext>()
            .UseSqlite(connection)
            .Options);
}
