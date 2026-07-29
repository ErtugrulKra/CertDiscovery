namespace CertificateDiscovery.Application.Acme;

public sealed record AcmeProblemDetails(string Code, string Message, bool Retryable);

