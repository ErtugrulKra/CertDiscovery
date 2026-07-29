namespace CertificateDiscovery.Application.Storage;

public sealed record CertificateStoreResult(string ExternalReference, DateTime StoredAtUtc, int? Version = null);
