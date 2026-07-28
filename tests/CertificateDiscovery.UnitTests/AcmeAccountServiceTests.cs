using CertificateDiscovery.Application.Acme;
using CertificateDiscovery.Application.Secrets;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Acme;
using CertificateDiscovery.Infrastructure.Persistence;
using CertificateDiscovery.Infrastructure.Secrets;
using CertificateDiscovery.Contracts;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace CertificateDiscovery.UnitTests;

public sealed class AcmeAccountServiceTests
{
    [Theory]
    [InlineData("AQIDBA", "AQIDBA")]
    [InlineData("AQIDBA==", "AQIDBA")]
    [InlineData("++//", "--__")]
    [InlineData("--__", "--__")]
    public void Eab_key_normalizes_base64_and_base64url(string input, string expected) =>
        Assert.Equal(expected, EabKeyNormalizer.Normalize(input));

    [Fact]
    public void Invalid_eab_key_is_rejected() =>
        Assert.Throws<ArgumentException>(() => EabKeyNormalizer.Normalize("not base64!?"));

    [Fact]
    public void Public_acme_dtos_never_expose_secret_values()
    {
        var propertyNames = typeof(AcmeProviderDto).GetProperties().Select(x => x.Name).ToList();

        Assert.DoesNotContain(propertyNames, x => x.Contains("HmacKey", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(propertyNames, x => x.Contains("AccountKey", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(propertyNames, x => x.Contains("SecretReference", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Eab_registration_requires_key_id_and_hmac_together()
    {
        var client = new CertesAcmeCertificateClient();
        var provider = new AcmeProvider { Name = "Sectigo", AccountEmail = "ops@example.com" };

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.RegisterAccountAsync(provider, "kid", null, default));

        Assert.Contains("together", error.Message);
    }

    [Fact]
    public async Task Protected_secret_round_trips_without_storing_plaintext()
    {
        await using var database = await TestDatabase.CreateAsync();
        var provider = new EphemeralDataProtectionProvider();
        var secrets = new ProtectedDbSecretProvider(database.Db, provider);

        var reference = await secrets.StoreAsync("test", "top-secret-value", default);
        var record = await database.Db.SecretRecords.SingleAsync();

        Assert.StartsWith("db-protected:", reference);
        Assert.DoesNotContain("top-secret-value", record.ProtectedValue);
        Assert.Equal("top-secret-value", await secrets.GetAsync(reference, default));
    }

    [Fact]
    public async Task Legacy_plaintext_eab_hmac_is_migrated_and_cleared()
    {
        await using var database = await TestDatabase.CreateAsync();
        var provider = new AcmeProvider
        {
            Name = "Legacy",
            AccountEmail = "ops@example.com",
            ExternalAccountBindingKeyId = "kid",
            ExternalAccountBindingHmacKey = "AQIDBA"
        };
        database.Db.AcmeProviders.Add(provider);
        await database.Db.SaveChangesAsync();
        var secrets = new ProtectedDbSecretProvider(database.Db, new EphemeralDataProtectionProvider());
        var migration = new LegacySecretMigrationService(database.Db, secrets);

        await migration.MigrateAsync(default);

        Assert.Null(provider.ExternalAccountBindingHmacKey);
        Assert.NotNull(provider.ExternalAccountBindingHmacSecretReference);
        Assert.Equal("AQIDBA", await secrets.GetAsync(provider.ExternalAccountBindingHmacSecretReference!, default));
    }

    [Fact]
    public async Task Multiple_requests_reuse_one_registered_account()
    {
        await using var database = await TestDatabase.CreateAsync();
        var provider = new AcmeProvider
        {
            Name = "Sectigo",
            ProviderType = AcmeProviderType.Sectigo,
            AccountEmail = "ops@example.com",
            ExternalAccountBindingKeyId = "kid",
            ExternalAccountBindingHmacSecretReference = "memory:hmac"
        };
        database.Db.AcmeProviders.Add(provider);
        await database.Db.SaveChangesAsync();
        var client = new RecordingAcmeClient();
        var secrets = new MemorySecretProvider(new Dictionary<string, string> { ["memory:hmac"] = "AQIDBA" });
        var service = new AcmeAccountService(database.Db, client, secrets);

        var first = await service.GetOrCreateAsync(provider, default);
        var second = await service.GetOrCreateAsync(provider, default);

        Assert.Equal(first.AccountId, second.AccountId);
        Assert.Equal(first.AccountLocation, second.AccountLocation);
        Assert.Equal(1, client.RegisterCount);
        Assert.Equal(1, await database.Db.AcmeAccounts.CountAsync());
        Assert.Equal(2, await database.Db.AcmeAccountEvents.CountAsync());
        Assert.Null(provider.ExternalAccountBindingHmacKey);
    }

    [Fact]
    public async Task Disabled_provider_cannot_register_an_account()
    {
        await using var database = await TestDatabase.CreateAsync();
        var provider = new AcmeProvider { Name = "Disabled", AccountEmail = "ops@example.com", IsEnabled = false };
        var service = new AcmeAccountService(database.Db, new RecordingAcmeClient(), new MemorySecretProvider());

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => service.GetOrCreateAsync(provider, default));

        Assert.Contains("disabled", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class RecordingAcmeClient : IAcmeCertificateClient
    {
        public int RegisterCount { get; private set; }

        public Task<AcmeAccountRegistration> RegisterAccountAsync(AcmeProvider provider, string? eabKeyId, string? eabHmacKey, CancellationToken cancellationToken)
        {
            RegisterCount++;
            Assert.Equal("kid", eabKeyId);
            Assert.Equal("AQIDBA", eabHmacKey);
            return Task.FromResult(new AcmeAccountRegistration("https://acme.test/account/1", "private-account-key"));
        }

        public Task TestDirectoryAsync(AcmeProvider provider, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task TestAccountAsync(AcmeProvider provider, AcmeAccountCredentials account, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<string> RotateAccountKeyAsync(AcmeProvider provider, AcmeAccountCredentials account, CancellationToken cancellationToken) => Task.FromResult("rotated-key");
        public Task<AcmeOrderContext> CreateOrderAsync(AcmeProvider provider, AcmeAccountCredentials account, IReadOnlyList<string> domains, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<IssuedCertificateBundle> ValidateAndFinalizeAsync(AcmeProvider provider, AcmeAccountCredentials account, AcmeOrderContext order, string commonName, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task RevokeAsync(AcmeProvider provider, string accountKeyPem, string certificatePem, CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class MemorySecretProvider(Dictionary<string, string>? initial = null) : ISecretProvider
    {
        private readonly Dictionary<string, string> values = initial ?? [];

        public Task<string> StoreAsync(string purpose, string value, CancellationToken cancellationToken)
        {
            var reference = $"memory:{Guid.NewGuid():D}";
            values[reference] = value;
            return Task.FromResult(reference);
        }

        public Task<string> GetAsync(string secretReference, CancellationToken cancellationToken) =>
            Task.FromResult(values.TryGetValue(secretReference, out var value)
                ? value
                : throw new InvalidOperationException("Secret not found."));

        public Task DeleteAsync(string secretReference, CancellationToken cancellationToken)
        {
            values.Remove(secretReference);
            return Task.CompletedTask;
        }
    }

    private sealed class TestDatabase : IAsyncDisposable
    {
        private readonly SqliteConnection connection;
        private TestDatabase(SqliteConnection connection, CertificateDiscoveryDbContext db)
        {
            this.connection = connection;
            Db = db;
        }

        public CertificateDiscoveryDbContext Db { get; }

        public static async Task<TestDatabase> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new CertificateDiscoveryDbContext(
                new DbContextOptionsBuilder<CertificateDiscoveryDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            return new TestDatabase(connection, db);
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await connection.DisposeAsync();
        }
    }
}
