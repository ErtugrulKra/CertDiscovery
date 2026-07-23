namespace CertificateDiscovery.IntegrationTests;

using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;

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
}
