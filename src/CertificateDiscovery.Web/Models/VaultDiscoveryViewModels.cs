namespace CertificateDiscovery.Web.Models;

using CertificateDiscovery.Contracts;

public sealed record VaultDiscoveryCreateViewModel(
    VaultDiscoveryJobCreateRequest Request,
    VaultDiscoveryCreateOptionsDto Options);
