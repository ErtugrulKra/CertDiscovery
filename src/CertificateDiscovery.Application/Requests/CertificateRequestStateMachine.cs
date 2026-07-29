using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Application.Requests;

public sealed class CertificateRequestStateMachine : ICertificateRequestStateMachine
{
    private static readonly IReadOnlyDictionary<CertificateRequestStatus, ISet<CertificateRequestStatus>> Transitions =
        new Dictionary<CertificateRequestStatus, ISet<CertificateRequestStatus>>
        {
            [CertificateRequestStatus.Draft] = new HashSet<CertificateRequestStatus> { CertificateRequestStatus.PendingDns, CertificateRequestStatus.Failed },
            [CertificateRequestStatus.PendingDns] = new HashSet<CertificateRequestStatus> { CertificateRequestStatus.Draft, CertificateRequestStatus.ReadyToValidate, CertificateRequestStatus.Validating, CertificateRequestStatus.Failed },
            [CertificateRequestStatus.ReadyToValidate] = new HashSet<CertificateRequestStatus> { CertificateRequestStatus.Draft, CertificateRequestStatus.Validating, CertificateRequestStatus.Failed },
            [CertificateRequestStatus.Validating] = new HashSet<CertificateRequestStatus> { CertificateRequestStatus.Issued, CertificateRequestStatus.ReadyToValidate, CertificateRequestStatus.Failed },
            [CertificateRequestStatus.Issued] = new HashSet<CertificateRequestStatus> { CertificateRequestStatus.Draft, CertificateRequestStatus.StoredInVault, CertificateRequestStatus.Failed },
            [CertificateRequestStatus.StoredInVault] = new HashSet<CertificateRequestStatus> { CertificateRequestStatus.Draft, CertificateRequestStatus.Failed },
            [CertificateRequestStatus.Failed] = new HashSet<CertificateRequestStatus> { CertificateRequestStatus.Draft, CertificateRequestStatus.PendingDns, CertificateRequestStatus.ReadyToValidate, CertificateRequestStatus.Validating }
        };

    public bool CanTransition(CertificateRequestStatus from, CertificateRequestStatus to) =>
        from == to || Transitions.TryGetValue(from, out var targets) && targets.Contains(to);

    public void Transition(AcmeCertificateRequest request, CertificateRequestStatus target)
    {
        if (!CanTransition(request.Status, target))
        {
            throw new InvalidOperationException($"Certificate request cannot transition from {request.Status} to {target}.");
        }

        request.Status = target;
        request.UpdatedAtUtc = DateTime.UtcNow;
    }
}
