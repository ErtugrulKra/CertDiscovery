using System.Text.Json;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Infrastructure.Deployment;

internal static class DeploymentVerificationEndpoints
{
    public static IReadOnlyList<Uri> Parse(DeploymentTarget target)
    {
        using var document = JsonDocument.Parse(
            string.IsNullOrWhiteSpace(target.ConfigurationJson) ? "{}" : target.ConfigurationJson);
        if (!document.RootElement.TryGetProperty("externalVerificationEndpoints", out var value) ||
            value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
            return [];
        if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() > 100)
            throw new InvalidOperationException("externalVerificationEndpoints must be an array containing at most 100 HTTPS URLs.");
        return value.EnumerateArray().Select(item =>
        {
            if (item.ValueKind != JsonValueKind.String ||
                !Uri.TryCreate(item.GetString(), UriKind.Absolute, out var endpoint) ||
                endpoint.Scheme != Uri.UriSchemeHttps || string.IsNullOrWhiteSpace(endpoint.Host))
                throw new InvalidOperationException("External verification endpoints must be absolute HTTPS URLs.");
            return endpoint;
        }).ToList();
    }
}
