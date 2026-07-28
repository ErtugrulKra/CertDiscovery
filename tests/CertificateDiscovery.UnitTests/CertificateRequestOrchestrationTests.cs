using CertificateDiscovery.Application.Acme;
using CertificateDiscovery.Application.Dns;
using CertificateDiscovery.Application.Inventory;
using CertificateDiscovery.Application.Requests;
using CertificateDiscovery.Application.Storage;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace CertificateDiscovery.UnitTests;

public sealed class CertificateRequestOrchestrationTests
{
    [Fact]
    public async Task Successful_issue_writes_inventory_stores_bundle_and_completes_request()
    {
        await using var fixture = await Fixture.CreateAsync(new SuccessfulAcmeClient());

        await fixture.Service.ValidateIssueAndStoreAsync(fixture.Request.Id, default);

        Assert.Equal(CertificateRequestStatus.StoredInVault, fixture.Request.Status);
        Assert.Equal(FakeInventoryWriter.CertificateId, fixture.Request.CertificateId);
        Assert.Equal("certificate", fixture.Request.CertificatePem);
        Assert.NotNull(fixture.Request.IssuedAtUtc);
        Assert.NotNull(fixture.Request.StoredAtUtc);
        Assert.Equal(1, fixture.Inventory.WriteCount);
        Assert.Equal(1, fixture.Store.WriteCount);
    }

    [Fact]
    public async Task Acme_timeout_leaves_request_retryable()
    {
        await using var fixture = await Fixture.CreateAsync(new ThrowingAcmeClient(new TimeoutException("DNS is pending.")));

        await Assert.ThrowsAsync<TimeoutException>(() =>
            fixture.Service.ValidateIssueAndStoreAsync(fixture.Request.Id, default));

        Assert.Equal(CertificateRequestStatus.ReadyToValidate, fixture.Request.Status);
        Assert.Equal("DNS is pending.", fixture.Request.ErrorMessage);
        Assert.Equal(0, fixture.Inventory.WriteCount);
        Assert.Equal(0, fixture.Store.WriteCount);
    }

    [Fact]
    public async Task Acme_failure_marks_request_failed()
    {
        await using var fixture = await Fixture.CreateAsync(new ThrowingAcmeClient(new InvalidOperationException("Authorization invalid.")));

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Service.ValidateIssueAndStoreAsync(fixture.Request.Id, default));

        Assert.Equal(CertificateRequestStatus.Failed, fixture.Request.Status);
        Assert.Equal("Authorization invalid.", fixture.Request.ErrorMessage);
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly SqliteConnection connection;

        private Fixture(
            SqliteConnection connection,
            CertificateDiscoveryDbContext db,
            CertificateRequestService service,
            AcmeCertificateRequest request,
            FakeInventoryWriter inventory,
            FakeCertificateStore store)
        {
            this.connection = connection;
            Db = db;
            Service = service;
            Request = request;
            Inventory = inventory;
            Store = store;
        }

        public CertificateDiscoveryDbContext Db { get; }
        public CertificateRequestService Service { get; }
        public AcmeCertificateRequest Request { get; }
        public FakeInventoryWriter Inventory { get; }
        public FakeCertificateStore Store { get; }

        public static async Task<Fixture> CreateAsync(IAcmeCertificateClient acmeClient)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new CertificateDiscoveryDbContext(
                new DbContextOptionsBuilder<CertificateDiscoveryDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            var acme = new AcmeProvider { Name = "Fake ACME", AccountEmail = "ops@example.com" };
            var vault = new VaultServer { Name = "Fake Vault", BaseUrl = new Uri("https://vault.test"), Token = "token" };
            var request = new AcmeCertificateRequest
            {
                Domain = "example.com",
                AcmeProvider = acme,
                AcmeProviderId = acme.Id,
                VaultServer = vault,
                VaultServerId = vault.Id,
                VaultSecretPath = "secret/certificates/example.com",
                Status = CertificateRequestStatus.PendingDns,
                AcmeAccountKeyPem = "account-key",
                AcmeOrderLocation = "https://acme.test/order/1"
            };
            var certificate = new Certificate
            {
                Id = FakeInventoryWriter.CertificateId,
                FingerprintSha256 = new string('A', 64),
                SerialNumber = "01",
                Subject = "CN=example.com",
                Issuer = "CN=issuer",
                NotBeforeUtc = DateTime.UtcNow.AddDays(-1),
                NotAfterUtc = DateTime.UtcNow.AddDays(89),
                Source = CertificateSource.Acme
            };
            db.AddRange(acme, vault, request, certificate);
            await db.SaveChangesAsync();
            var inventory = new FakeInventoryWriter();
            var store = new FakeCertificateStore();
            var service = new CertificateRequestService(
                db,
                acmeClient,
                new FakeAcmeAccountService(),
                new UnsupportedDnsResolver(),
                store,
                inventory,
                new CertificateRequestStateMachine());
            return new Fixture(connection, db, service, request, inventory, store);
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await connection.DisposeAsync();
        }
    }

    private sealed class SuccessfulAcmeClient : IAcmeCertificateClient
    {
        public Task TestDirectoryAsync(AcmeProvider provider, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task TestAccountAsync(AcmeProvider provider, AcmeAccountCredentials account, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<string> RotateAccountKeyAsync(AcmeProvider provider, AcmeAccountCredentials account, CancellationToken cancellationToken) => Task.FromResult("rotated-key");

        public Task<AcmeAccountRegistration> RegisterAccountAsync(AcmeProvider provider, string? eabKeyId, string? eabHmacKey, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<IssuedCertificateBundle> ValidateAndFinalizeAsync(AcmeProvider provider, AcmeAccountCredentials account, AcmeOrderContext order, string commonName, CancellationToken cancellationToken) =>
            Task.FromResult(new IssuedCertificateBundle("certificate", "full-chain", "private-key"));

        public Task<AcmeOrderContext> CreateOrderAsync(AcmeProvider provider, AcmeAccountCredentials account, IReadOnlyList<string> domains, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task RevokeAsync(AcmeProvider provider, string accountKeyPem, string certificatePem, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class ThrowingAcmeClient(Exception exception) : IAcmeCertificateClient
    {
        public Task TestDirectoryAsync(AcmeProvider provider, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task TestAccountAsync(AcmeProvider provider, AcmeAccountCredentials account, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<string> RotateAccountKeyAsync(AcmeProvider provider, AcmeAccountCredentials account, CancellationToken cancellationToken) => Task.FromResult("rotated-key");

        public Task<AcmeAccountRegistration> RegisterAccountAsync(AcmeProvider provider, string? eabKeyId, string? eabHmacKey, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<IssuedCertificateBundle> ValidateAndFinalizeAsync(AcmeProvider provider, AcmeAccountCredentials account, AcmeOrderContext order, string commonName, CancellationToken cancellationToken) =>
            Task.FromException<IssuedCertificateBundle>(exception);

        public Task<AcmeOrderContext> CreateOrderAsync(AcmeProvider provider, AcmeAccountCredentials account, IReadOnlyList<string> domains, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task RevokeAsync(AcmeProvider provider, string accountKeyPem, string certificatePem, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class FakeAcmeAccountService : IAcmeAccountService
    {
        public Task<AcmeAccountCredentials> GetOrCreateAsync(AcmeProvider provider, CancellationToken cancellationToken) =>
            Task.FromResult(new AcmeAccountCredentials(Guid.Empty, "https://acme.test/account/1", "account-key"));

        public Task<AcmeAccountCredentials> GetCredentialsAsync(Guid accountId, CancellationToken cancellationToken) =>
            Task.FromResult(new AcmeAccountCredentials(accountId, "https://acme.test/account/1", "account-key"));

        public Task DisableAsync(Guid accountId, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task RotateKeyAsync(Guid accountId, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    public sealed class FakeInventoryWriter : ICertificateInventoryWriter
    {
        public static readonly Guid CertificateId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        public int WriteCount { get; private set; }

        public Task<Guid> UpsertAsync(CertificateInventoryContext context, CancellationToken cancellationToken)
        {
            WriteCount++;
            return Task.FromResult(CertificateId);
        }
    }

    public sealed class FakeCertificateStore : ICertificateStore
    {
        public int WriteCount { get; private set; }

        public Task<CertificateStoreResult> StoreAsync(CertificateStoreContext context, CancellationToken cancellationToken)
        {
            WriteCount++;
            return Task.FromResult(new CertificateStoreResult(context.Request.VaultSecretPath, DateTime.UtcNow));
        }
    }

    private sealed class UnsupportedDnsResolver : IDnsChallengeProviderResolver
    {
        public IDnsChallengeProvider Resolve(DnsProviderType providerType) => throw new NotSupportedException();
    }
}
