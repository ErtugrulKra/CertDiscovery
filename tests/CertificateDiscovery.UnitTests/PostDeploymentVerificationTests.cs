using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Deployment;

namespace CertificateDiscovery.UnitTests;

public sealed class PostDeploymentVerificationTests
{
    [Theory]
    [InlineData(VerificationQuorumMode.All, 100, 3, 3, DeploymentVerificationOutcome.Verified)]
    [InlineData(VerificationQuorumMode.All, 100, 2, 3, DeploymentVerificationOutcome.Failed)]
    [InlineData(VerificationQuorumMode.Any, 100, 1, 3, DeploymentVerificationOutcome.Verified)]
    [InlineData(VerificationQuorumMode.Percentage, 66, 2, 3, DeploymentVerificationOutcome.Verified)]
    [InlineData(VerificationQuorumMode.Percentage, 80, 2, 3, DeploymentVerificationOutcome.Failed)]
    public void Evaluates_quorum_modes(
        VerificationQuorumMode mode, int percentage, int successful, int total,
        DeploymentVerificationOutcome expected)
    {
        var nodes = Enumerable.Range(0, total)
            .Select(index => new VerificationNodeResult(index < successful, index < successful ? "NEW" : null))
            .ToList();
        var result = VerificationQuorumEvaluator.Evaluate(nodes, mode, percentage, 1, "NEW");
        Assert.Equal(expected, result.Outcome);
    }

    [Fact]
    public void Detects_partial_rollout_even_when_percentage_quorum_is_met()
    {
        var nodes = new[]
        {
            new VerificationNodeResult(true, "NEW"),
            new VerificationNodeResult(true, "NEW"),
            new VerificationNodeResult(false, "OLD")
        };
        var result = VerificationQuorumEvaluator.Evaluate(
            nodes, VerificationQuorumMode.Percentage, 60, 1, "NEW");
        Assert.Equal(DeploymentVerificationOutcome.PartiallyVerified, result.Outcome);
        Assert.Equal(2, result.DistinctFingerprints);
    }

    [Theory]
    [InlineData("api.example.com", "*.example.com", true)]
    [InlineData("deep.api.example.com", "*.example.com", false)]
    [InlineData("example.com", "example.com", true)]
    [InlineData("other.example.com", "example.com", false)]
    public void Matches_exact_and_single_label_wildcard_SAN(string host, string san, bool expected) =>
        Assert.Equal(expected, TlsEndpointVerifier.MatchesDnsName(host, [san]));

    [Fact]
    public async Task Produces_structured_endpoint_results_and_partial_quorum()
    {
        var endpoints = new[] { new Uri("https://a.example.com"), new Uri("https://b.example.com") };
        var probe = new FakeProbe(new Dictionary<string, string>
        {
            ["a.example.com"] = "NEW",
            ["b.example.com"] = "OLD"
        });
        var verifier = new TlsEndpointVerifier(probe);
        var policy = new DeploymentPolicy
        {
            VerificationQuorumMode = VerificationQuorumMode.All,
            VerificationAttempts = 1
        };
        var result = await verifier.VerifyAsync(endpoints, "NEW", policy, default);
        Assert.Equal(DeploymentVerificationOutcome.PartiallyVerified, result.Quorum.Outcome);
        Assert.Equal(2, result.Endpoints.Count);
        Assert.Contains(result.Endpoints, x => x.Outcome == EndpointVerificationOutcome.Verified);
        Assert.Contains(result.Endpoints, x => x.Outcome == EndpointVerificationOutcome.FingerprintMismatch);
        Assert.All(result.Endpoints, x => Assert.DoesNotContain("PRIVATE KEY", x.PublicChainJson));
    }

    [Theory]
    [InlineData("other.example.com", -1, 30, true, EndpointVerificationOutcome.SanMismatch)]
    [InlineData("example.com", -30, -1, true, EndpointVerificationOutcome.Expired)]
    [InlineData("example.com", 1, 30, true, EndpointVerificationOutcome.NotYetValid)]
    [InlineData("example.com", -1, 30, false, EndpointVerificationOutcome.ChainInvalid)]
    public async Task Classifies_SAN_time_and_chain_failures(
        string san, int notBeforeDays, int notAfterDays, bool chainValid,
        EndpointVerificationOutcome expected)
    {
        var endpoint = new Uri("https://example.com");
        var probe = new SingleObservationProbe(new(
            endpoint, "10.0.0.1", "EXPECTED", "CN=example.com", "CN=Test CA",
            DateTime.UtcNow.AddDays(notBeforeDays), DateTime.UtcNow.AddDays(notAfterDays), [san],
            [], chainValid, null, null, 2));
        var result = await new TlsEndpointVerifier(probe).VerifyAsync(
            [endpoint], "EXPECTED", new DeploymentPolicy(), default);
        Assert.Equal(expected, Assert.Single(result.Endpoints).Outcome);
        Assert.Equal(DeploymentVerificationOutcome.Failed, result.Quorum.Outcome);
    }

    [Fact]
    public void State_machine_supports_partial_verification_lifecycle()
    {
        var stateMachine = new DeploymentStateMachine();
        var deployment = new CertificateDeployment { Status = CertificateDeploymentStatus.Verifying };
        stateMachine.Transition(deployment, CertificateDeploymentStatus.PartiallyVerified);
        stateMachine.Transition(deployment, CertificateDeploymentStatus.Verifying);
        stateMachine.Transition(deployment, CertificateDeploymentStatus.Succeeded);
        Assert.Equal(CertificateDeploymentStatus.Succeeded, deployment.Status);
    }

    private sealed class FakeProbe(IReadOnlyDictionary<string, string> fingerprints) : ITlsCertificateProbe
    {
        public Task<TlsCertificateObservation> ProbeAsync(Uri endpoint, CancellationToken cancellationToken) =>
            Task.FromResult(new TlsCertificateObservation(
                endpoint, endpoint.Host == "a.example.com" ? "10.0.0.1" : "10.0.0.2",
                fingerprints[endpoint.Host], $"CN={endpoint.Host}", "CN=Test CA",
                DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30), [endpoint.Host],
                [new PublicCertificateChainEntry(0, $"CN={endpoint.Host}", "CN=Test CA",
                    fingerprints[endpoint.Host], DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30))],
                true, null, null, 5));
    }

    private sealed class SingleObservationProbe(TlsCertificateObservation observation) : ITlsCertificateProbe
    {
        public Task<TlsCertificateObservation> ProbeAsync(Uri endpoint, CancellationToken cancellationToken) =>
            Task.FromResult(observation);
    }
}
