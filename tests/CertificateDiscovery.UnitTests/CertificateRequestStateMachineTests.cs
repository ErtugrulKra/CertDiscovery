using CertificateDiscovery.Application.Requests;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Dns;

namespace CertificateDiscovery.UnitTests;

public sealed class CertificateRequestStateMachineTests
{
    private readonly CertificateRequestStateMachine stateMachine = new();

    [Theory]
    [InlineData(CertificateRequestStatus.Draft, CertificateRequestStatus.PendingDns)]
    [InlineData(CertificateRequestStatus.PendingDns, CertificateRequestStatus.ReadyToValidate)]
    [InlineData(CertificateRequestStatus.ReadyToValidate, CertificateRequestStatus.Validating)]
    [InlineData(CertificateRequestStatus.Validating, CertificateRequestStatus.Issued)]
    [InlineData(CertificateRequestStatus.Issued, CertificateRequestStatus.StoredInVault)]
    [InlineData(CertificateRequestStatus.StoredInVault, CertificateRequestStatus.Draft)]
    [InlineData(CertificateRequestStatus.Failed, CertificateRequestStatus.PendingDns)]
    public void Allows_legal_transition(CertificateRequestStatus from, CertificateRequestStatus to)
    {
        var request = new AcmeCertificateRequest { Status = from };

        stateMachine.Transition(request, to);

        Assert.Equal(to, request.Status);
        Assert.NotNull(request.UpdatedAtUtc);
    }

    [Fact]
    public void Rejects_invalid_transition()
    {
        var request = new AcmeCertificateRequest { Status = CertificateRequestStatus.Draft };

        var error = Assert.Throws<InvalidOperationException>(() =>
            stateMachine.Transition(request, CertificateRequestStatus.StoredInVault));

        Assert.Contains("Draft to StoredInVault", error.Message);
        Assert.Equal(CertificateRequestStatus.Draft, request.Status);
    }

    [Fact]
    public void Resolver_reports_unsupported_provider()
    {
        var resolver = new DnsChallengeProviderResolver([new ManualDnsChallengeProvider()]);

        var error = Assert.Throws<NotSupportedException>(() => resolver.Resolve(DnsProviderType.Cloudflare));

        Assert.Contains("Cloudflare", error.Message);
    }
}
