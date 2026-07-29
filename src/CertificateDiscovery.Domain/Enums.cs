using System.ComponentModel.DataAnnotations;

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
public enum AcmeProviderType { Generic, LetsEncrypt, ZeroSsl, Buypass, GoogleTrustServices, Sectigo, Custom }
public enum AcmeAccountStatus { Active, Disabled, Deactivated }
public enum DnsProviderType { Cloudflare, Generic, Route53, AzureDns }
public enum AwsDnsAuthenticationMode { DefaultCredentialChain, AssumeRole, WorkloadIdentity, StaticCredentials }
public enum AzureDnsAuthenticationMode { DefaultAzureCredential, ManagedIdentity, WorkloadIdentity, ServicePrincipal }
public enum CertificateRequestType { Standard, Wildcard }
public enum CertificateRequestStatus { Draft, PendingDns, ReadyToValidate, Validating, Issued, StoredInVault, Failed }
public enum AcmeChallengeType { ManualDns01 }
public enum DeploymentTargetType
{
    [Display(Name = "Fake (Test Only)")] Fake,
    [Display(Name = "Microsoft IIS")] Iis,
    [Display(Name = "NGNIX")] Nginx,
    [Display(Name = "Kubernetes")] Kubernetes,
    [Display(Name = "Azure App Service")] AzureAppService,
    [Display(Name = "AWS Load Balancer")] AwsLoadBalancer,
    [Display(Name = "HA Proxy")] HaProxy,
    [Display(Name = "Traefik")] Traefik,
    [Display(Name = "Apache Web Server")] ApacheWebServer,
    [Display(Name = "Vault KV")] VaultKv,
    [Display(Name = "File System Export")] FileSystem
}
public enum CertificateDeploymentStatus
{
    Pending, AwaitingApproval, Prechecking, BackingUp, Deploying, Activating, Verifying,
    Succeeded, Failed, RollingBack, RolledBack, RollbackFailed, Cancelled, Rejected
}
public enum DeploymentJobStatus { Pending, Claimed, Completed, DeadLetter, Cancelled }
public enum DeploymentOrigin { Manual, Automatic, Retry }
public enum DeploymentAgentStatus
{
    PendingRegistration, Online, Busy, Stale, Offline, Disabled, Revoked, UpgradeRequired
}
public enum AgentDeploymentJobStatus { Pending, Claimed, Completed, Failed, RolledBack, DeadLetter }
public enum DeploymentAgentExchangeStatus { Pending, Approved, Rejected, Expired, Completed }
