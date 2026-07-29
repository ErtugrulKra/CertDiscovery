using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Application.Deployment;

public sealed class DeploymentStateMachine : IDeploymentStateMachine
{
    private static readonly IReadOnlyDictionary<CertificateDeploymentStatus, ISet<CertificateDeploymentStatus>> Transitions =
        new Dictionary<CertificateDeploymentStatus, ISet<CertificateDeploymentStatus>>
        {
            [CertificateDeploymentStatus.Pending] = Set(CertificateDeploymentStatus.AwaitingApproval, CertificateDeploymentStatus.Prechecking, CertificateDeploymentStatus.Failed, CertificateDeploymentStatus.Cancelled),
            [CertificateDeploymentStatus.AwaitingApproval] = Set(CertificateDeploymentStatus.Pending, CertificateDeploymentStatus.Rejected, CertificateDeploymentStatus.Cancelled),
            [CertificateDeploymentStatus.Prechecking] = Set(CertificateDeploymentStatus.BackingUp, CertificateDeploymentStatus.Failed),
            [CertificateDeploymentStatus.BackingUp] = Set(CertificateDeploymentStatus.Deploying, CertificateDeploymentStatus.Failed),
            [CertificateDeploymentStatus.Deploying] = Set(CertificateDeploymentStatus.Activating, CertificateDeploymentStatus.Failed, CertificateDeploymentStatus.RollingBack),
            [CertificateDeploymentStatus.Activating] = Set(CertificateDeploymentStatus.Verifying, CertificateDeploymentStatus.Failed, CertificateDeploymentStatus.RollingBack),
            [CertificateDeploymentStatus.Verifying] = Set(CertificateDeploymentStatus.PartiallyVerified, CertificateDeploymentStatus.Succeeded, CertificateDeploymentStatus.Failed, CertificateDeploymentStatus.RollingBack),
            [CertificateDeploymentStatus.PartiallyVerified] = Set(CertificateDeploymentStatus.Verifying, CertificateDeploymentStatus.Succeeded, CertificateDeploymentStatus.Failed, CertificateDeploymentStatus.RollingBack),
            [CertificateDeploymentStatus.Failed] = Set(CertificateDeploymentStatus.Pending, CertificateDeploymentStatus.RollingBack, CertificateDeploymentStatus.Cancelled),
            [CertificateDeploymentStatus.RollingBack] = Set(CertificateDeploymentStatus.RolledBack, CertificateDeploymentStatus.RollbackFailed),
            [CertificateDeploymentStatus.Succeeded] = Set(CertificateDeploymentStatus.RollingBack),
            [CertificateDeploymentStatus.RollbackFailed] = Set(CertificateDeploymentStatus.RollingBack),
            [CertificateDeploymentStatus.RolledBack] = Set(),
            [CertificateDeploymentStatus.Cancelled] = Set(),
            [CertificateDeploymentStatus.Rejected] = Set()
        };

    public bool CanTransition(CertificateDeploymentStatus from, CertificateDeploymentStatus to) =>
        from == to || Transitions.TryGetValue(from, out var allowed) && allowed.Contains(to);

    public void Transition(CertificateDeployment deployment, CertificateDeploymentStatus target)
    {
        if (!CanTransition(deployment.Status, target))
            throw new InvalidOperationException($"Deployment transition from {deployment.Status} to {target} is not allowed.");
        deployment.Status = target;
        deployment.UpdatedAtUtc = DateTime.UtcNow;
    }

    private static HashSet<CertificateDeploymentStatus> Set(params CertificateDeploymentStatus[] values) => [.. values];
}
