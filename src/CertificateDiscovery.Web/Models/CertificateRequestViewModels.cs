namespace CertificateDiscovery.Web.Models;

using CertificateDiscovery.Contracts;

public sealed record CertificateRequestCreateViewModel(
    CertificateRequestCreateRequest Request,
    CertificateRequestCreateOptionsDto Options);
