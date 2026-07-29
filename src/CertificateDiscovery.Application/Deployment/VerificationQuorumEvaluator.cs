using CertificateDiscovery.Domain;

namespace CertificateDiscovery.Application.Deployment;

public sealed record VerificationNodeResult(bool Succeeded, string? ObservedFingerprint);
public sealed record VerificationQuorumResult(
    DeploymentVerificationOutcome Outcome,
    int TotalNodes,
    int SuccessfulNodes,
    int RequiredSuccessfulNodes,
    int DistinctFingerprints,
    string Message);

public static class VerificationQuorumEvaluator
{
    public static VerificationQuorumResult Evaluate(
        IReadOnlyCollection<VerificationNodeResult> nodes,
        VerificationQuorumMode mode,
        int quorumPercentage,
        int minimumSuccessfulNodes,
        string expectedFingerprint)
    {
        if (nodes.Count == 0)
            return new(DeploymentVerificationOutcome.Failed, 0, 0, Math.Max(1, minimumSuccessfulNodes), 0,
                "No TLS endpoints were available for verification.");
        if (quorumPercentage is < 1 or > 100)
            throw new ArgumentOutOfRangeException(nameof(quorumPercentage), "Quorum percentage must be between 1 and 100.");
        if (minimumSuccessfulNodes < 1)
            throw new ArgumentOutOfRangeException(nameof(minimumSuccessfulNodes), "Minimum successful nodes must be at least one.");

        var successful = nodes.Count(x => x.Succeeded &&
            string.Equals(x.ObservedFingerprint, expectedFingerprint, StringComparison.OrdinalIgnoreCase));
        var required = mode switch
        {
            VerificationQuorumMode.Any => minimumSuccessfulNodes,
            VerificationQuorumMode.Percentage => Math.Max(
                minimumSuccessfulNodes,
                (int)Math.Ceiling(nodes.Count * quorumPercentage / 100d)),
            _ => nodes.Count
        };
        var fingerprints = nodes.Select(x => x.ObservedFingerprint)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();
        var hasExpected = nodes.Any(x => string.Equals(x.ObservedFingerprint, expectedFingerprint, StringComparison.OrdinalIgnoreCase));
        var hasUnexpected = nodes.Any(x => !string.IsNullOrWhiteSpace(x.ObservedFingerprint) &&
            !string.Equals(x.ObservedFingerprint, expectedFingerprint, StringComparison.OrdinalIgnoreCase));
        var outcome = hasExpected && hasUnexpected
            ? DeploymentVerificationOutcome.PartiallyVerified
            : successful >= required
                ? DeploymentVerificationOutcome.Verified
                : DeploymentVerificationOutcome.Failed;
        var message = outcome switch
        {
            DeploymentVerificationOutcome.Verified => $"{successful}/{nodes.Count} node(s) met the {mode} verification quorum.",
            DeploymentVerificationOutcome.PartiallyVerified => $"Partial rollout detected: expected and unexpected certificates are served across {nodes.Count} node(s).",
            _ => $"Verification quorum failed: {successful}/{nodes.Count} node(s) succeeded; {required} required."
        };
        return new(outcome, nodes.Count, successful, required, fingerprints, message);
    }
}
