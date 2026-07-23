namespace CertificateDiscovery.Contracts;

using CertificateDiscovery.Domain;

public sealed record DiscoveryJobCreateRequest(
    string Name,
    string Cidr,
    string Ports,
    int TimeoutSeconds,
    int MaxConcurrency);

public sealed record DiscoveryJobDto(
    Guid Id,
    string Name,
    string Cidr,
    string Ports,
    ScanJobStatus Status,
    DateTime RequestedAtUtc,
    DateTime? StartedAtUtc,
    DateTime? CompletedAtUtc,
    int TotalEndpointCount,
    int ScannedEndpointCount,
    int CertificateFoundCount,
    int FailedEndpointCount,
    int TimeoutSeconds,
    int MaxConcurrency,
    string? WorkerId,
    string? ErrorMessage,
    string RequestedBy,
    long? DurationMilliseconds);

public sealed record DiscoveredEndpointDto(
    Guid Id,
    Guid DiscoveryJobId,
    string IpAddress,
    int Port,
    AssetProtocol ProtocolGuess,
    ScanResultStatus Status,
    DateTime StartedAtUtc,
    DateTime CompletedAtUtc,
    long DurationMilliseconds,
    string? TlsProtocol,
    string? CipherSuite,
    Guid? CertificateId,
    string? CertificateCommonName,
    string? CertificateFingerprintSha256,
    DateTime? CertificateNotAfterUtc,
    string? ReverseDnsName,
    ScanErrorType ErrorType,
    string? ErrorMessage,
    Guid? PromotedAssetId);

public sealed record WorkerDiscoveryJobDto(
    Guid JobId,
    string Cidr,
    IReadOnlyList<int> Ports,
    int TimeoutSeconds,
    int MaxConcurrency);

public sealed record WorkerDiscoveryResultRequest(
    Guid DiscoveryJobId,
    string IpAddress,
    int Port,
    AssetProtocol ProtocolGuess,
    ScanResultStatus Status,
    DateTime StartedAtUtc,
    DateTime CompletedAtUtc,
    long DurationMilliseconds,
    string? TlsProtocol,
    string? CipherSuite,
    WorkerCertificateDto? Certificate,
    string? ReverseDnsName,
    ScanErrorType ErrorType,
    string? ErrorMessage,
    string? RawDiagnosticData);

public sealed record WorkerDiscoveryCompleteRequest(string WorkerName);
public sealed record WorkerDiscoveryFailRequest(string WorkerName, string ErrorMessage);
