using CertificateDiscovery.Domain;
using CertificateDiscovery.Infrastructure.Dns;

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
}
