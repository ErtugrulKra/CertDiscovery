using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Application.Requests;

public interface ICertificateRequestStateMachine
{
    bool CanTransition(CertificateRequestStatus from, CertificateRequestStatus to);
    void Transition(AcmeCertificateRequest request, CertificateRequestStatus target);
}

