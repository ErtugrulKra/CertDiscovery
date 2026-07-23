namespace CertificateDiscovery.Contracts;

using CertificateDiscovery.Domain;

public sealed record ScanJobDto(
    Guid Id,
    ScanJobStatus Status,
    ScanTriggerType TriggerType,
    DateTime RequestedAtUtc,
    DateTime? StartedAtUtc,
    DateTime? CompletedAtUtc,
    int TotalAssetCount,
    int SuccessfulAssetCount,
    int FailedAssetCount,
    string? WorkerId,
    string? ErrorMessage,
    long? DurationMilliseconds);

public sealed record ScanJobCreateRequest(IReadOnlyList<Guid>? AssetIds, ScanTriggerType TriggerType);
public sealed record ScanJobClaimRequest(string WorkerName);
public sealed record ScanJobCompleteRequest(string WorkerName);
public sealed record ScanJobFailRequest(string WorkerName, string ErrorMessage);

public sealed record ScanResultDto(
    Guid Id,
    Guid ScanJobId,
    Guid AssetId,
    string AssetName,
    ScanResultStatus Status,
    DateTime StartedAtUtc,
    DateTime CompletedAtUtc,
    long DurationMilliseconds,
    string? ResolvedIpAddress,
    string? TlsProtocol,
    string? CipherSuite,
    Guid? CertificateId,
    ScanErrorType ErrorType,
    string? ErrorMessage,
    string? RawDiagnosticData);

public sealed record WorkerJobDto(Guid JobId, IReadOnlyList<WorkerAssetDto> Assets);

public sealed record WorkerAssetDto(
    Guid Id,
    string Name,
    string Host,
    int Port,
    AssetProtocol Protocol,
    string? SniHost,
    int TimeoutSeconds);

public sealed record WorkerScanResultRequest(
    Guid ScanJobId,
    Guid AssetId,
    ScanResultStatus Status,
    DateTime StartedAtUtc,
    DateTime CompletedAtUtc,
    long DurationMilliseconds,
    string? ResolvedIpAddress,
    string? TlsProtocol,
    string? CipherSuite,
    WorkerCertificateDto? Certificate,
    ScanErrorType ErrorType,
    string? ErrorMessage,
    string? RawDiagnosticData);

public sealed record WorkerCertificateDto(
    string FingerprintSha256,
    string? SerialNumber,
    string Subject,
    string? CommonName,
    string Issuer,
    DateTime NotBeforeUtc,
    DateTime NotAfterUtc,
    string? SignatureAlgorithm,
    string? PublicKeyAlgorithm,
    int? PublicKeySize,
    int? Version,
    bool IsSelfSigned,
    string? PemEncodedCertificate,
    IReadOnlyList<SubjectAlternativeNameDto> SubjectAlternativeNames,
    IReadOnlyList<WorkerCertificateChainEntryDto>? ChainEntries = null);

public sealed record WorkerCertificateChainEntryDto(
    int Position,
    string FingerprintSha256,
    string? SerialNumber,
    string Subject,
    string? CommonName,
    string Issuer,
    DateTime NotBeforeUtc,
    DateTime NotAfterUtc,
    string? SignatureAlgorithm,
    string? PublicKeyAlgorithm,
    int? PublicKeySize,
    int? Version,
    bool IsSelfSigned,
    string? PemEncodedCertificate);
