namespace CertificateDiscovery.Domain;

public enum AssetProtocol { HTTPS, TLS, SMTPS, IMAPS, POP3S, LDAPS }
public enum AssetType { WebApplication, Api, LoadBalancer, ReverseProxy, MailServer, DirectoryServer, Database, Other }
public enum AssetEnvironment { Development, Test, Staging, Production, Other }
public enum ScanJobStatus { Pending, Running, Completed, PartiallyCompleted, Failed, Cancelled }
public enum ScanTriggerType { Scheduled, Manual, Retry }
public enum ScanResultStatus { Success, Failed }
public enum ScanErrorType
{
    None,
    DnsResolutionFailed,
    ConnectionTimeout,
    ConnectionRefused,
    TlsHandshakeFailed,
    CertificateParseFailed,
    UnsupportedProtocol,
    InternalError
}
public enum WorkerStatus { Online, Stale, Offline }
public enum CertificateSanType { DNS, IP, Email, URI, Other }
public enum CertificateHealthStatus { Expired, Critical, Warning, Attention, Healthy }
public enum CertificateSource { Scan, NetworkDiscovery, VaultPublicEndpoint, VaultPki, VaultKv, Acme }
public enum AcmeProviderType { Generic, LetsEncrypt, ZeroSsl, Buypass, GoogleTrustServices, Custom }
public enum DnsProviderType { Cloudflare, Generic }
public enum CertificateRequestType { Standard, Wildcard }
public enum CertificateRequestStatus { Draft, PendingDns, ReadyToValidate, Validating, Issued, StoredInVault, Failed }
public enum AcmeChallengeType { ManualDns01 }
