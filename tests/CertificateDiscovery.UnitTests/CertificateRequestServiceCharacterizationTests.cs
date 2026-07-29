using System.Net;
using System.Text;
using CertificateDiscovery.Application.Acme;
using CertificateDiscovery.Application.Dns;
using CertificateDiscovery.Application.Inventory;
using CertificateDiscovery.Application.Requests;
using CertificateDiscovery.Application.Storage;
using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using CertificateDiscovery.Infrastructure.Services;
using CertificateDiscovery.Infrastructure.Dns;
using CertificateDiscovery.Infrastructure.Inventory;
using CertificateDiscovery.Infrastructure.Storage;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace CertificateDiscovery.UnitTests;

public sealed class CertificateRequestServiceCharacterizationTests
{
    [Fact]
    public async Task Create_standard_request_normalizes_domain_and_sans()
    {
        await using var fixture = await RequestFixture.CreateAsync();

        var id = await fixture.Service.CreateAsync(fixture.Input(
            CertificateRequestType.Standard, " Example.COM. ", "WWW.Example.com; api.example.com\nwww.example.com"), default);

        var request = await fixture.Db.AcmeCertificateRequests.FindAsync(id);
        Assert.Equal("example.com", request!.Domain);
        Assert.Equal("www.example.com, api.example.com", request.SubjectAlternativeNames);
        Assert.Equal(CertificateRequestStatus.Draft, request.Status);
        Assert.Equal("secret/certificates/example.com", request.VaultSecretPath);
    }

    [Fact]
    public async Task Create_wildcard_request_adds_base_domain_to_sans()
    {
        await using var fixture = await RequestFixture.CreateAsync();

        var id = await fixture.Service.CreateAsync(
            fixture.Input(CertificateRequestType.Wildcard, "*.Example.COM.", "api.example.com"), default);

        var request = await fixture.Db.AcmeCertificateRequests.FindAsync(id);
        Assert.Equal("*.example.com", request!.Domain);
        Assert.Equal("example.com, api.example.com", request.SubjectAlternativeNames);
    }

    [Fact]
    public async Task Start_dns_challenge_persists_provider_independent_instructions()
    {
        await using var fixture = await RequestFixture.CreateAsync();
        var request = fixture.SeedRequest(CertificateRequestStatus.Draft);
        request.SubjectAlternativeNames = "www.example.com";
        await fixture.Db.SaveChangesAsync();

        await fixture.Service.StartManualDnsChallengeAsync(request.Id, default);

        Assert.Equal(CertificateRequestStatus.PendingDns, request.Status);
        Assert.Equal("_acme-challenge.example.com\n_acme-challenge.www.example.com", request.DnsTxtName);
        Assert.Equal("value-example.com\nvalue-www.example.com", request.DnsTxtValue);
        Assert.Equal("https://acme.test/order/1", request.AcmeOrderLocation);
        Assert.Equal(FakeAcmeAccountService.AccountId, request.AcmeAccountId);
        Assert.Null(request.AcmeAccountKeyPem);
    }

    [Fact]
    public async Task Cloudflare_publish_and_cleanup_use_only_exact_challenge_values()
    {
        var handler = new CloudflareHandler();
        await using var fixture = await RequestFixture.CreateAsync(handler);
        var request = fixture.SeedRequest(CertificateRequestStatus.PendingDns);
        request.DnsTxtName = "_acme-challenge.example.com";
        request.DnsTxtValue = "owned-value";
        await fixture.Db.SaveChangesAsync();

        await fixture.Service.PublishDnsChallengeAsync(request.Id, default);
        await fixture.Service.CleanupDnsChallengeAsync(request.Id, default);

        Assert.Contains(handler.Requests, x => x.Method == HttpMethod.Put && x.Path.EndsWith("/dns_records/owned-id") && x.Body.Contains("\"content\":\"owned-value\""));
        Assert.Contains(handler.Requests, x => x.Method == HttpMethod.Delete && x.Path.EndsWith("/dns_records/owned-id"));
        Assert.DoesNotContain(handler.Requests, x => x.Method == HttpMethod.Delete && x.Path.EndsWith("/dns_records/unrelated-id"));
        Assert.Equal("Bearer test-cloudflare-token", handler.Authorization);
    }

    [Fact]
    public async Task Vault_store_uses_kv_v2_path_and_complete_bundle()
    {
        var handler = new VaultHandler();
        await using var fixture = await RequestFixture.CreateAsync(handler);
        var request = fixture.SeedRequest(CertificateRequestStatus.Issued);
        request.IssuedAtUtc = DateTime.UtcNow;

        await fixture.Store.StoreAsync(
            new CertificateStoreContext(request, fixture.Vault, fixture.Acme, ["example.com"], "leaf-pem", "private-key-pem", "chain-pem", "ABC123"),
            CancellationToken.None);

        Assert.Equal("/v1/secret/data/certificates/example.com", handler.Path);
        Assert.Equal("test-vault-token", handler.VaultToken);
        Assert.Contains("\"certificate_pem\":\"leaf-pem\"", handler.Body);
        Assert.Contains("\"private_key_pem\":\"private-key-pem\"", handler.Body);
        Assert.Contains("\"fullchain_pem\":\"chain-pem\"", handler.Body);
        Assert.Contains("\"fingerprint_sha256\":\"ABC123\"", handler.Body);
    }

    [Fact]
    public async Task Scheduled_check_reschedules_certificate_outside_renewal_threshold()
    {
        await using var fixture = await RequestFixture.CreateAsync();
        var request = fixture.SeedRequest(CertificateRequestStatus.StoredInVault);
        request.ScheduleCheck = true;
        request.NextScheduleCheckAtUtc = DateTime.UtcNow.AddMinutes(-1);
        var certificate = new Certificate
        {
            FingerprintSha256 = new string('A', 64),
            Subject = "CN=example.com",
            Issuer = "CN=issuer",
            SerialNumber = "01",
            NotBeforeUtc = DateTime.UtcNow.AddDays(-1),
            NotAfterUtc = DateTime.UtcNow.AddDays(90),
            Source = CertificateSource.Acme
        };
        fixture.Db.Certificates.Add(certificate);
        await fixture.Db.SaveChangesAsync();
        request.CertificateId = certificate.Id;
        request.Certificate = certificate;
        await fixture.Db.SaveChangesAsync();

        var processed = await fixture.Service.RunDueScheduledChecksAsync(default);

        Assert.Equal(1, processed);
        Assert.Equal("Valid", request.LastScheduleCheckStatus);
        Assert.True(request.NextScheduleCheckAtUtc > DateTime.UtcNow);
    }

    [Fact]
    public async Task Scheduled_renewal_reuses_the_persistent_acme_account()
    {
        await using var fixture = await RequestFixture.CreateAsync();
        var request = fixture.SeedRequest(CertificateRequestStatus.StoredInVault);
        request.AcmeAccountId = FakeAcmeAccountService.AccountId;
        request.DnsProvider = null;
        request.DnsProviderId = null;
        request.ScheduleCheck = true;
        request.NextScheduleCheckAtUtc = DateTime.UtcNow.AddMinutes(-1);
        var certificate = new Certificate
        {
            FingerprintSha256 = new string('B', 64),
            Subject = "CN=example.com",
            Issuer = "CN=issuer",
            SerialNumber = "02",
            NotBeforeUtc = DateTime.UtcNow.AddDays(-89),
            NotAfterUtc = DateTime.UtcNow.AddDays(1),
            Source = CertificateSource.Acme
        };
        fixture.Db.Certificates.Add(certificate);
        await fixture.Db.SaveChangesAsync();
        request.CertificateId = certificate.Id;
        request.Certificate = certificate;
        await fixture.Db.SaveChangesAsync();

        await fixture.Service.RunScheduledCheckAsync(request.Id, default);

        Assert.Equal(FakeAcmeAccountService.AccountId, request.AcmeAccountId);
        Assert.Equal(CertificateRequestStatus.PendingDns, request.Status);
        Assert.Equal("WaitingForManualDns", request.LastScheduleCheckStatus);
        Assert.Null(request.AcmeAccountKeyPem);
    }

    private sealed class RequestFixture : IAsyncDisposable
    {
        private readonly SqliteConnection connection;

        private RequestFixture(SqliteConnection connection, CertificateDiscoveryDbContext db, CertificateRequestService service, ICertificateStore store)
        {
            this.connection = connection;
            Db = db;
            Service = service;
            Store = store;
        }

        public CertificateDiscoveryDbContext Db { get; }
        public CertificateRequestService Service { get; }
        public ICertificateStore Store { get; }
        public AcmeProvider Acme { get; private init; } = null!;
        public VaultServer Vault { get; private init; } = null!;
        public DnsProvider Dns { get; private init; } = null!;

        public static async Task<RequestFixture> CreateAsync(HttpMessageHandler? handler = null)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var options = new DbContextOptionsBuilder<CertificateDiscoveryDbContext>().UseSqlite(connection).Options;
            var db = new CertificateDiscoveryDbContext(options);
            await db.Database.EnsureCreatedAsync();
            var acme = new AcmeProvider { Name = "Test ACME", AccountEmail = "ops@example.com" };
            var vault = new VaultServer { Name = "Test Vault", BaseUrl = new Uri("https://vault.test"), Token = "test-vault-token" };
            var dns = new DnsProvider { Name = "Test DNS", ZoneName = "example.com", ApiToken = "test-cloudflare-token" };
            db.AddRange(acme, vault, dns);
            await db.SaveChangesAsync();
            db.AcmeAccounts.Add(new AcmeAccount
            {
                Id = FakeAcmeAccountService.AccountId,
                AcmeProviderId = acme.Id,
                AccountLocation = "https://acme.test/account/1",
                AccountKeySecretReference = "test-secret",
                ContactEmail = acme.AccountEmail
            });
            await db.SaveChangesAsync();
            var httpFactory = new TestHttpClientFactory(handler);
            var cloudflare = new CloudflareDnsChallengeProvider(httpFactory);
            var resolver = new DnsChallengeProviderResolver([new ManualDnsChallengeProvider(), cloudflare]);
            var store = new VaultKvCertificateStore(httpFactory);
            var inventory = new CertificateInventoryWriter(db);
            var service = new CertificateRequestService(
                db,
                new FakeAcmeClient(),
                new FakeAcmeAccountService(),
                resolver,
                store,
                inventory,
                new CertificateRequestStateMachine());
            return new RequestFixture(connection, db, service, store)
            {
                Acme = acme,
                Vault = vault,
                Dns = dns
            };
        }

        public CertificateRequestCreateRequest Input(CertificateRequestType type, string domain, string? sans) =>
            new(type, domain, sans, Acme.Id, Vault.Id, null, "", false, 5, "0 0 * * *");

        public AcmeCertificateRequest SeedRequest(CertificateRequestStatus status)
        {
            var request = new AcmeCertificateRequest
            {
                Domain = "example.com",
                AcmeProviderId = Acme.Id,
                AcmeProvider = Acme,
                VaultServerId = Vault.Id,
                VaultServer = Vault,
                DnsProviderId = Dns.Id,
                DnsProvider = Dns,
                VaultSecretPath = "secret/certificates/example.com",
                Status = status
            };
            Db.AcmeCertificateRequests.Add(request);
            return request;
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await connection.DisposeAsync();
        }
    }

    private sealed class FakeAcmeClient : IAcmeCertificateClient
    {
        public Task TestDirectoryAsync(AcmeProvider provider, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task TestAccountAsync(AcmeProvider provider, AcmeAccountCredentials account, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<string> RotateAccountKeyAsync(AcmeProvider provider, AcmeAccountCredentials account, CancellationToken cancellationToken) => Task.FromResult("rotated-key");

        public Task<AcmeAccountRegistration> RegisterAccountAsync(AcmeProvider provider, string? eabKeyId, string? eabHmacKey, CancellationToken cancellationToken) =>
            Task.FromResult(new AcmeAccountRegistration("https://acme.test/account/1", "account-key"));

        public Task<AcmeOrderContext> CreateOrderAsync(AcmeProvider provider, AcmeAccountCredentials account, IReadOnlyList<string> domains, CancellationToken cancellationToken) =>
            Task.FromResult(new AcmeOrderContext("account-key", "https://acme.test/order/1", domains.Select(x =>
                new AcmeChallengeResult(x, $"_acme-challenge.{x.TrimStart('*').TrimStart('.')}", $"value-{x}")).ToList()));

        public Task<IssuedCertificateBundle> ValidateAndFinalizeAsync(AcmeProvider provider, AcmeAccountCredentials account, AcmeOrderContext order, string commonName, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task RevokeAsync(AcmeProvider provider, string accountKeyPem, string certificatePem, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class FakeAcmeAccountService : IAcmeAccountService
    {
        public static readonly Guid AccountId = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");

        public Task<AcmeAccountCredentials> GetOrCreateAsync(AcmeProvider provider, CancellationToken cancellationToken) =>
            Task.FromResult(new AcmeAccountCredentials(AccountId, "https://acme.test/account/1", "account-key"));

        public Task<AcmeAccountCredentials> GetCredentialsAsync(Guid accountId, CancellationToken cancellationToken) =>
            Task.FromResult(new AcmeAccountCredentials(accountId, "https://acme.test/account/1", "account-key"));

        public Task DisableAsync(Guid accountId, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task RotateKeyAsync(Guid accountId, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class TestHttpClientFactory(HttpMessageHandler? handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler ?? new EmptyHandler(), disposeHandler: false);
    }

    private sealed class EmptyHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException($"Unexpected HTTP request: {request.RequestUri}");
    }

    private sealed class CloudflareHandler : HttpMessageHandler
    {
        public List<(HttpMethod Method, string Path, string Body)> Requests { get; } = [];
        public string? Authorization { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.PathAndQuery;
            var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
            Requests.Add((request.Method, path, body));
            Authorization = request.Headers.Authorization?.ToString();
            var json = path.StartsWith("/client/v4/zones?") ? """{"success":true,"result":[{"id":"zone-id"}]}"""
                : request.Method == HttpMethod.Get ? """{"success":true,"result":[{"id":"unrelated-id","content":"keep-me"},{"id":"owned-id","content":"owned-value"}]}"""
                : """{"success":true,"result":{}}""";
            return Json(json);
        }
    }

    private sealed class VaultHandler : HttpMessageHandler
    {
        public string? Path { get; private set; }
        public string? Body { get; private set; }
        public string? VaultToken { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Path = request.RequestUri!.AbsolutePath;
            Body = await request.Content!.ReadAsStringAsync(cancellationToken);
            VaultToken = request.Headers.GetValues("X-Vault-Token").Single();
            return Json("""{"data":{"version":1}}""");
        }
    }

    private static HttpResponseMessage Json(string value) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(value, Encoding.UTF8, "application/json")
    };
}
