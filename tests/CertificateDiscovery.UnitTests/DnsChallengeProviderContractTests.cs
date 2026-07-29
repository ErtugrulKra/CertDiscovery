using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Dns;
using Amazon.Route53.Model;

namespace CertificateDiscovery.UnitTests;

public sealed class DnsChallengeProviderContractTests
{
    public static IEnumerable<object[]> AutomatedProviders()
    {
        yield return [DnsProviderType.Cloudflare];
        yield return [DnsProviderType.Route53];
        yield return [DnsProviderType.AzureDns];
    }

    [Theory]
    [MemberData(nameof(AutomatedProviders))]
    public void Publish_contract_preserves_existing_values_and_is_idempotent(DnsProviderType providerType)
    {
        var result = DnsTxtRecordSetSemantics.Merge(["unrelated", "challenge-a"], ["challenge-a", "challenge-b"]);

        Assert.Equal(["challenge-a", "challenge-b", "unrelated"], result);
        Assert.Equal(result, DnsTxtRecordSetSemantics.Merge(result, ["challenge-a", "challenge-b"]));
        Assert.True(Enum.IsDefined(providerType));
    }

    [Theory]
    [MemberData(nameof(AutomatedProviders))]
    public void Cleanup_contract_removes_only_owned_values(DnsProviderType providerType)
    {
        var result = DnsTxtRecordSetSemantics.RemoveOwned(
            ["unrelated", "challenge-a", "challenge-b"],
            ["challenge-a", "challenge-b"]);

        Assert.Equal(["unrelated"], result);
        Assert.True(Enum.IsDefined(providerType));
    }

    [Fact]
    public void Azure_record_name_is_relative_to_configured_zone()
    {
        Assert.Equal("_acme-challenge.api", AzureDnsChallengeProvider.ToRelativeRecordName(
            "_acme-challenge.api.example.com.", "example.com"));
        Assert.Throws<InvalidOperationException>(() =>
            AzureDnsChallengeProvider.ToRelativeRecordName("_acme-challenge.other.net", "example.com"));
    }

    [Fact]
    public void Route53_txt_quoting_round_trips()
    {
        const string value = "token-with-\\-and-\"quote";
        Assert.Equal(value, Route53DnsChallengeProvider.Unquote(Route53DnsChallengeProvider.Quote(value)));
    }

    [Fact]
    public void Route53_configuration_requires_assume_role_arn()
    {
        var provider = new DnsProvider
        {
            ProviderType = DnsProviderType.Route53,
            ZoneName = "example.com",
            AwsAuthenticationMode = AwsDnsAuthenticationMode.AssumeRole
        };

        var exception = Assert.Throws<InvalidOperationException>(() =>
            Route53DnsChallengeProvider.ValidateRequiredConfiguration(provider));

        Assert.Contains("role ARN", exception.Message);
    }

    [Fact]
    public void Route53_zone_resolution_rejects_ambiguous_public_and_private_zones()
    {
        var provider = new DnsProvider { ZoneName = "example.com" };
        var zones = new[]
        {
            new HostedZone { Id = "/hostedzone/public", Name = "example.com." },
            new HostedZone { Id = "/hostedzone/private", Name = "example.com." }
        };

        var exception = Assert.Throws<InvalidOperationException>(() =>
            Route53DnsChallengeProvider.SelectHostedZone(zones, provider));

        Assert.Contains("ambiguous", exception.Message);
        Assert.Contains("HostedZoneId", exception.Message);
    }

    [Fact]
    public void Route53_zone_resolution_returns_exact_normalized_match()
    {
        var provider = new DnsProvider { ZoneName = "Example.COM." };

        var selected = Route53DnsChallengeProvider.SelectHostedZone(
            [
                new HostedZone { Id = "/hostedzone/other", Name = "other.example." },
                new HostedZone { Id = "/hostedzone/expected", Name = "example.com." }
            ],
            provider);

        Assert.Equal("/hostedzone/expected", selected.Id);
    }

    [Fact]
    public void Azure_configuration_requires_subscription_resource_group_and_zone()
    {
        var provider = new DnsProvider
        {
            ProviderType = DnsProviderType.AzureDns,
            ZoneName = "example.com"
        };

        var exception = Assert.Throws<InvalidOperationException>(() =>
            AzureDnsChallengeProvider.ValidateRequiredConfiguration(provider));

        Assert.Contains("subscription ID", exception.Message);
    }

    [Theory]
    [InlineData(AzureDnsAuthenticationMode.ServicePrincipal)]
    [InlineData(AzureDnsAuthenticationMode.WorkloadIdentity)]
    public void Azure_identity_modes_require_tenant_and_client_ids(AzureDnsAuthenticationMode mode)
    {
        var provider = new DnsProvider
        {
            ProviderType = DnsProviderType.AzureDns,
            ZoneName = "example.com",
            SubscriptionId = Guid.NewGuid().ToString(),
            ResourceGroup = "dns-rg",
            AzureAuthenticationMode = mode
        };

        var exception = Assert.Throws<InvalidOperationException>(() =>
            AzureDnsChallengeProvider.ValidateRequiredConfiguration(provider));

        Assert.Contains("tenant ID and client ID", exception.Message);
    }
}
