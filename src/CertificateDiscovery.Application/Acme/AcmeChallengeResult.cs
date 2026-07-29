namespace CertificateDiscovery.Application.Acme;

public sealed record AcmeChallengeResult(string Identifier, string RecordName, string RecordValue);

