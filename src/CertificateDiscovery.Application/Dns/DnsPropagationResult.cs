namespace CertificateDiscovery.Application.Dns;

public sealed record DnsPropagationResult(bool IsPropagated, IReadOnlyList<string> ObservedValues, string? Message = null);

