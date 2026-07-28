using System.Net;
using System.Reflection;
using System.Text;
using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using CertificateDiscovery.Infrastructure.Services;
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
        request.CertificatePem = "leaf-pem";
        request.FullChainPem = "chain-pem";
        request.CertificatePrivateKeyPem = "private-key-pem";
        request.IssuedAtUtc = DateTime.UtcNow;

        await InvokePrivateAsync(fixture.Service, "StoreInVaultAsync", request, CancellationToken.None);

        Assert.Equal("/v1/secret/data/certificates/example.com", handler.Path);
        Assert.Equal("test-vault-token", handler.VaultToken);
        Assert.Contains("\"certificate_pem\":\"leaf-pem\"", handler.Body);
        Assert.Contains("\"private_key_pem\":\"private-key-pem\"", handler.Body);
        Assert.Contains("\"fullchain_pem\":\"chain-pem\"", handler.Body);
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

    private static async Task InvokePrivateAsync(object target, string name, params object[] arguments)
    {
        var method = target.GetType().GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException($"Method {name} was not found.");
        await (Task)(method.Invoke(target, arguments)
            ?? throw new InvalidOperationException($"Method {name} returned null."));
    }

    private sealed class RequestFixture : IAsyncDisposable
    {
        private readonly SqliteConnection connection;

        private RequestFixture(SqliteConnection connection, CertificateDiscoveryDbContext db, CertificateRequestService service)
        {
            this.connection = connection;
            Db = db;
            Service = service;
        }

        public CertificateDiscoveryDbContext Db { get; }
        public CertificateRequestService Service { get; }
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
            return new RequestFixture(connection, db, new CertificateRequestService(db, new TestHttpClientFactory(handler)))
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
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

    private static HttpResponseMessage Json(string value) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(value, Encoding.UTF8, "application/json")
    };
}
