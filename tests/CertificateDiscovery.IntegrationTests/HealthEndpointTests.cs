namespace CertificateDiscovery.IntegrationTests;

using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.Extensions.DependencyInjection;

public sealed class HealthEndpointTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public HealthEndpointTests(WebApplicationFactory<Program> factory)
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"cert-discovery-{Guid.NewGuid():N}.db");
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("ConnectionStrings:DefaultConnection", $"Data Source={dbPath}");
            builder.UseSetting("CertificateDiscovery:ApplyMigrationsOnStartup", "false");
            builder.UseSetting("CertificateDiscovery:SchedulerEnabled", "false");
            builder.ConfigureLogging(logging => logging.ClearProviders());
        });
    }

    [Fact]
    public async Task Health_ReturnsSuccess()
    {
        var client = _factory.CreateClient();
        var response = await client.GetAsync("/health");

        response.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task Metrics_exposes_deployment_metric_contract()
    {
        await using (var scope = _factory.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateDiscoveryDbContext>();
            await db.Database.EnsureCreatedAsync();
        }
        var response = await _factory.CreateClient().GetAsync("/metrics");
        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadAsStringAsync();
        Assert.Contains("# HELP certificate_discovery_deployments_total", content);
        Assert.Contains("# HELP certificate_discovery_deployment_retries_total", content);
        Assert.Contains("# HELP certificate_discovery_deployment_rollbacks_total", content);
        Assert.Contains("# HELP certificate_discovery_deployment_verifications_total", content);
    }
}
