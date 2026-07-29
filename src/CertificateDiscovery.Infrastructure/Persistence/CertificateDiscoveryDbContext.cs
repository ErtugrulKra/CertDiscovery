namespace CertificateDiscovery.Infrastructure.Persistence;

using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using Microsoft.EntityFrameworkCore;

public sealed class CertificateDiscoveryDbContext(DbContextOptions<CertificateDiscoveryDbContext> options) : DbContext(options)
{
    public DbSet<Asset> Assets => Set<Asset>();
    public DbSet<Certificate> Certificates => Set<Certificate>();
    public DbSet<CertificateChainEntry> CertificateChainEntries => Set<CertificateChainEntry>();
    public DbSet<CertificateSubjectAlternativeName> CertificateSubjectAlternativeNames => Set<CertificateSubjectAlternativeName>();
    public DbSet<VaultServer> VaultServers => Set<VaultServer>();
    public DbSet<AcmeProvider> AcmeProviders => Set<AcmeProvider>();
    public DbSet<AcmeAccount> AcmeAccounts => Set<AcmeAccount>();
    public DbSet<AcmeAccountEvent> AcmeAccountEvents => Set<AcmeAccountEvent>();
    public DbSet<SecretRecord> SecretRecords => Set<SecretRecord>();
    public DbSet<DnsProvider> DnsProviders => Set<DnsProvider>();
    public DbSet<AcmeCertificateRequest> AcmeCertificateRequests => Set<AcmeCertificateRequest>();
    public DbSet<AssetCertificate> AssetCertificates => Set<AssetCertificate>();
    public DbSet<ScanJob> ScanJobs => Set<ScanJob>();
    public DbSet<ScanJobAsset> ScanJobAssets => Set<ScanJobAsset>();
    public DbSet<ScanResult> ScanResults => Set<ScanResult>();
    public DbSet<WorkerNode> WorkerNodes => Set<WorkerNode>();
    public DbSet<AppSetting> AppSettings => Set<AppSetting>();
    public DbSet<AppUser> AppUsers => Set<AppUser>();
    public DbSet<DiscoveryJob> DiscoveryJobs => Set<DiscoveryJob>();
    public DbSet<DiscoveredEndpoint> DiscoveredEndpoints => Set<DiscoveredEndpoint>();
    public DbSet<VaultDiscoveryJob> VaultDiscoveryJobs => Set<VaultDiscoveryJob>();
    public DbSet<VaultDiscoveryResult> VaultDiscoveryResults => Set<VaultDiscoveryResult>();
    public DbSet<DeploymentTarget> DeploymentTargets => Set<DeploymentTarget>();
    public DbSet<DeploymentPolicy> DeploymentPolicies => Set<DeploymentPolicy>();
    public DbSet<CertificateDeployment> CertificateDeployments => Set<CertificateDeployment>();
    public DbSet<DeploymentJob> DeploymentJobs => Set<DeploymentJob>();
    public DbSet<DeploymentAuditEvent> DeploymentAuditEvents => Set<DeploymentAuditEvent>();
    public DbSet<DeploymentVerificationRun> DeploymentVerificationRuns => Set<DeploymentVerificationRun>();
    public DbSet<DeploymentEndpointVerification> DeploymentEndpointVerifications => Set<DeploymentEndpointVerification>();
    public DbSet<DeploymentAgent> DeploymentAgents => Set<DeploymentAgent>();
    public DbSet<DeploymentAgentRegistrationToken> DeploymentAgentRegistrationTokens => Set<DeploymentAgentRegistrationToken>();
    public DbSet<DeploymentAgentRegistrationExchange> DeploymentAgentRegistrationExchanges => Set<DeploymentAgentRegistrationExchange>();
    public DbSet<AgentDeploymentJob> AgentDeploymentJobs => Set<AgentDeploymentJob>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<DeploymentAgent>(entity =>
        {
            entity.Property(x => x.Name).HasMaxLength(160).IsRequired();
            entity.Property(x => x.MachineName).HasMaxLength(255).IsRequired();
            entity.Property(x => x.AgentType).HasMaxLength(80).IsRequired();
            entity.Property(x => x.Version).HasMaxLength(80).IsRequired();
            entity.Property(x => x.OperatingSystem).HasMaxLength(255).IsRequired();
            entity.Property(x => x.CapabilitiesJson).IsRequired();
            entity.Property(x => x.Status).HasConversion<string>().HasMaxLength(40);
            entity.Property(x => x.AuthenticationTokenHash).HasMaxLength(128).IsRequired();
            entity.Property(x => x.PublicKeyPem).HasMaxLength(16384);
            entity.HasIndex(x => x.MachineName);
            entity.HasIndex(x => x.LastHeartbeatAtUtc);
            entity.HasIndex(x => x.Status);
        });
        modelBuilder.Entity<DeploymentAgentRegistrationToken>(entity =>
        {
            entity.Property(x => x.TokenHash).HasMaxLength(128).IsRequired();
            entity.Property(x => x.Description).HasMaxLength(255).IsRequired();
            entity.Property(x => x.CreatedBy).HasMaxLength(160);
            entity.HasIndex(x => x.TokenHash).IsUnique();
            entity.HasIndex(x => x.ExpiresAtUtc);
        });
        modelBuilder.Entity<DeploymentAgentRegistrationExchange>(entity =>
        {
            entity.Property(x => x.ExchangeSecretHash).HasMaxLength(128).IsRequired();
            entity.Property(x => x.UserCode).HasMaxLength(16).IsRequired();
            entity.Property(x => x.Name).HasMaxLength(160).IsRequired();
            entity.Property(x => x.MachineName).HasMaxLength(255).IsRequired();
            entity.Property(x => x.Version).HasMaxLength(80).IsRequired();
            entity.Property(x => x.OperatingSystem).HasMaxLength(255).IsRequired();
            entity.Property(x => x.CapabilitiesJson).IsRequired();
            entity.Property(x => x.PublicKeyPem).HasMaxLength(16384).IsRequired();
            entity.Property(x => x.PublicKeyFingerprint).HasMaxLength(128).IsRequired();
            entity.Property(x => x.Status).HasConversion<string>().HasMaxLength(40);
            entity.Property(x => x.ApprovedBy).HasMaxLength(160);
            entity.Property(x => x.RejectedBy).HasMaxLength(160);
            entity.HasIndex(x => x.ExchangeSecretHash).IsUnique();
            entity.HasIndex(x => x.UserCode).IsUnique();
            entity.HasIndex(x => new { x.Status, x.ExpiresAtUtc });
            entity.HasOne(x => x.RegisteredAgent).WithMany().HasForeignKey(x => x.RegisteredAgentId).OnDelete(DeleteBehavior.SetNull);
        });
        modelBuilder.Entity<AgentDeploymentJob>(entity =>
        {
            entity.Property(x => x.Status).HasConversion<string>().HasMaxLength(40);
            entity.Property(x => x.TargetConfigurationJson).IsRequired();
            entity.Property(x => x.LeaseTokenHash).HasMaxLength(128);
            entity.Property(x => x.Stage).HasMaxLength(80);
            entity.Property(x => x.ObservedFingerprint).HasMaxLength(128);
            entity.Property(x => x.PreviousFingerprint).HasMaxLength(128);
            entity.Property(x => x.ErrorCode).HasMaxLength(120);
            entity.Property(x => x.ErrorMessage).HasMaxLength(2048);
            entity.HasIndex(x => new { x.DeploymentAgentId, x.Status, x.CreatedAtUtc });
            entity.HasIndex(x => x.CertificateDeploymentId).IsUnique();
            entity.HasOne(x => x.DeploymentAgent).WithMany().HasForeignKey(x => x.DeploymentAgentId).OnDelete(DeleteBehavior.Restrict);
            entity.HasOne(x => x.CertificateDeployment).WithMany().HasForeignKey(x => x.CertificateDeploymentId).OnDelete(DeleteBehavior.Cascade);
        });
        modelBuilder.Entity<Asset>(entity =>
        {
            entity.Property(x => x.Name).HasMaxLength(160).IsRequired();
            entity.Property(x => x.Host).HasMaxLength(255).IsRequired();
            entity.Property(x => x.Protocol).HasConversion<string>().HasMaxLength(20);
            entity.Property(x => x.Environment).HasConversion<string>().HasMaxLength(40);
            entity.Property(x => x.AssetType).HasConversion<string>().HasMaxLength(40);
            entity.Property(x => x.Owner).HasMaxLength(120);
            entity.HasIndex(x => new { x.Host, x.Port, x.Protocol });
        });

        modelBuilder.Entity<Certificate>(entity =>
        {
            entity.Property(x => x.FingerprintSha256).HasMaxLength(128).IsRequired();
            entity.Property(x => x.Subject).HasMaxLength(1024).IsRequired();
            entity.Property(x => x.Issuer).HasMaxLength(1024).IsRequired();
            entity.Property(x => x.CommonName).HasMaxLength(255);
            entity.Property(x => x.Source).HasConversion<string>().HasMaxLength(40);
            entity.Property(x => x.SourceName).HasMaxLength(160);
            entity.Property(x => x.ExternalReference).HasMaxLength(512);
            entity.HasIndex(x => x.FingerprintSha256).IsUnique();
        });

        modelBuilder.Entity<CertificateSubjectAlternativeName>(entity =>
        {
            entity.Property(x => x.Name).HasMaxLength(512).IsRequired();
            entity.Property(x => x.Type).HasConversion<string>().HasMaxLength(20);
            entity.HasIndex(x => new { x.CertificateId, x.Name, x.Type }).IsUnique();
        });

        modelBuilder.Entity<CertificateChainEntry>(entity =>
        {
            entity.Property(x => x.FingerprintSha256).HasMaxLength(128).IsRequired();
            entity.Property(x => x.Subject).HasMaxLength(1024).IsRequired();
            entity.Property(x => x.Issuer).HasMaxLength(1024).IsRequired();
            entity.Property(x => x.CommonName).HasMaxLength(255);
            entity.HasIndex(x => x.CertificateId);
            entity.HasIndex(x => new { x.CertificateId, x.Position }).IsUnique();
            entity.HasIndex(x => x.FingerprintSha256);
        });

        modelBuilder.Entity<AssetCertificate>(entity =>
        {
            entity.HasIndex(x => new { x.AssetId, x.CertificateId });
            entity.HasIndex(x => x.IsCurrentlyActive);
        });

        modelBuilder.Entity<ScanJob>(entity =>
        {
            entity.Property(x => x.Status).HasConversion<string>().HasMaxLength(40);
            entity.Property(x => x.TriggerType).HasConversion<string>().HasMaxLength(40);
            entity.HasIndex(x => x.Status);
            entity.HasIndex(x => x.RequestedAtUtc);
        });

        modelBuilder.Entity<ScanJobAsset>(entity =>
        {
            entity.HasKey(x => new { x.ScanJobId, x.AssetId });
        });

        modelBuilder.Entity<ScanResult>(entity =>
        {
            entity.Property(x => x.Status).HasConversion<string>().HasMaxLength(40);
            entity.Property(x => x.ErrorType).HasConversion<string>().HasMaxLength(60);
            entity.HasIndex(x => x.ScanJobId);
            entity.HasIndex(x => x.AssetId);
        });

        modelBuilder.Entity<WorkerNode>(entity =>
        {
            entity.Property(x => x.WorkerName).HasMaxLength(160).IsRequired();
            entity.Property(x => x.Description).HasMaxLength(512);
            entity.Property(x => x.Status).HasMaxLength(40).IsRequired();
            entity.HasIndex(x => x.WorkerName).IsUnique();
            entity.HasIndex(x => x.LastHeartbeatAtUtc);
        });

        modelBuilder.Entity<AppSetting>(entity =>
        {
            entity.Property(x => x.Key).HasMaxLength(120).IsRequired();
            entity.Property(x => x.Value).HasMaxLength(512).IsRequired();
            entity.Property(x => x.Description).HasMaxLength(512);
            entity.HasIndex(x => x.Key).IsUnique();
        });

        modelBuilder.Entity<VaultServer>(entity =>
        {
            entity.Property(x => x.Name).HasMaxLength(160).IsRequired();
            entity.Property(x => x.BaseUrl).HasConversion(x => x.ToString(), x => new Uri(x)).HasMaxLength(512).IsRequired();
            entity.Property(x => x.Description).HasMaxLength(512);
            entity.Property(x => x.PkiMountPath).HasMaxLength(160);
            entity.Property(x => x.Token).HasMaxLength(2048);
            entity.Property(x => x.LastSyncStatus).HasMaxLength(60);
            entity.HasIndex(x => x.Name).IsUnique();
            entity.HasIndex(x => x.IsEnabled);
        });

        modelBuilder.Entity<AcmeProvider>(entity =>
        {
            entity.Property(x => x.Name).HasMaxLength(160).IsRequired();
            entity.Property(x => x.ProviderType).HasConversion<string>().HasMaxLength(60);
            entity.Property(x => x.DirectoryUrl).HasConversion(x => x.ToString(), x => new Uri(x)).HasMaxLength(512).IsRequired();
            entity.Property(x => x.AccountEmail).HasMaxLength(255).IsRequired();
            entity.Property(x => x.ExternalAccountBindingKeyId).HasMaxLength(255);
            entity.Property(x => x.ExternalAccountBindingHmacKey).HasMaxLength(2048);
            entity.Property(x => x.ExternalAccountBindingHmacSecretReference).HasMaxLength(512);
            entity.Property(x => x.Organization).HasMaxLength(255);
            entity.Property(x => x.Department).HasMaxLength(255);
            entity.Property(x => x.CertificateProfile).HasMaxLength(255);
            entity.Property(x => x.ProductType).HasMaxLength(120);
            entity.Property(x => x.AllowedDomainPattern).HasMaxLength(512);
            entity.Property(x => x.Notes).HasMaxLength(1024);
            entity.HasIndex(x => x.Name).IsUnique();
            entity.HasIndex(x => x.IsEnabled);
        });

        modelBuilder.Entity<AcmeAccount>(entity =>
        {
            entity.Property(x => x.AccountLocation).HasMaxLength(1024).IsRequired();
            entity.Property(x => x.AccountKeySecretReference).HasMaxLength(512).IsRequired();
            entity.Property(x => x.ExternalAccountBindingKeyId).HasMaxLength(255);
            entity.Property(x => x.Status).HasConversion<string>().HasMaxLength(40);
            entity.Property(x => x.ContactEmail).HasMaxLength(255).IsRequired();
            entity.HasIndex(x => x.AcmeProviderId)
                .IsUnique()
                .HasFilter("\"Status\" = 'Active'");
            entity.HasOne(x => x.AcmeProvider)
                .WithMany(x => x.Accounts)
                .HasForeignKey(x => x.AcmeProviderId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<SecretRecord>(entity =>
        {
            entity.Property(x => x.Purpose).HasMaxLength(255).IsRequired();
            entity.Property(x => x.ProtectedValue).IsRequired();
            entity.HasIndex(x => x.Purpose);
        });

        modelBuilder.Entity<AcmeAccountEvent>(entity =>
        {
            entity.Property(x => x.EventType).HasMaxLength(80).IsRequired();
            entity.Property(x => x.Message).HasMaxLength(1024);
            entity.HasIndex(x => x.AcmeProviderId);
            entity.HasIndex(x => x.AcmeAccountId);
            entity.HasIndex(x => x.CreatedAtUtc);
        });

        modelBuilder.Entity<DnsProvider>(entity =>
        {
            entity.Property(x => x.Name).HasMaxLength(160).IsRequired();
            entity.Property(x => x.ProviderType).HasConversion<string>().HasMaxLength(60);
            entity.Property(x => x.ZoneName).HasMaxLength(255).IsRequired();
            entity.Property(x => x.ApiToken).HasMaxLength(2048);
            entity.Property(x => x.ApiTokenSecretReference).HasMaxLength(512);
            entity.Property(x => x.HostedZoneId).HasMaxLength(255);
            entity.Property(x => x.AwsAuthenticationMode).HasConversion<string>().HasMaxLength(60);
            entity.Property(x => x.RoleArn).HasMaxLength(512);
            entity.Property(x => x.AccessKeySecretReference).HasMaxLength(512);
            entity.Property(x => x.SecretKeySecretReference).HasMaxLength(512);
            entity.Property(x => x.SessionTokenSecretReference).HasMaxLength(512);
            entity.Property(x => x.Region).HasMaxLength(80);
            entity.Property(x => x.AzureAuthenticationMode).HasConversion<string>().HasMaxLength(60);
            entity.Property(x => x.TenantId).HasMaxLength(255);
            entity.Property(x => x.SubscriptionId).HasMaxLength(255);
            entity.Property(x => x.ResourceGroup).HasMaxLength(255);
            entity.Property(x => x.ClientId).HasMaxLength(255);
            entity.Property(x => x.ClientSecretReference).HasMaxLength(512);
            entity.Property(x => x.ManagedIdentityClientId).HasMaxLength(255);
            entity.Property(x => x.LastHealthCheckStatus).HasMaxLength(80);
            entity.Property(x => x.LastHealthCheckError).HasMaxLength(2048);
            entity.Property(x => x.Notes).HasMaxLength(1024);
            entity.HasIndex(x => x.Name).IsUnique();
            entity.HasIndex(x => x.IsEnabled);
        });

        modelBuilder.Entity<AcmeCertificateRequest>(entity =>
        {
            entity.Property(x => x.Domain).HasMaxLength(255).IsRequired();
            entity.Property(x => x.SubjectAlternativeNames).HasMaxLength(1024);
            entity.Property(x => x.ChallengeType).HasConversion<string>().HasMaxLength(40);
            entity.Property(x => x.Status).HasConversion<string>().HasMaxLength(40);
            entity.Property(x => x.VaultSecretPath).HasMaxLength(512).IsRequired();
            entity.Property(x => x.DnsTxtName).HasMaxLength(2048);
            entity.Property(x => x.DnsTxtValue).HasMaxLength(4096);
            entity.Property(x => x.AcmeOrderLocation).HasMaxLength(1024);
            entity.Property(x => x.ErrorMessage).HasMaxLength(2048);
            entity.Property(x => x.DnsPublishStatus).HasMaxLength(120);
            entity.Property(x => x.DnsPublishError).HasMaxLength(2048);
            entity.Property(x => x.RenewalCronExpression).HasMaxLength(120);
            entity.Property(x => x.LastScheduleCheckStatus).HasMaxLength(120);
            entity.Property(x => x.LastScheduleCheckMessage).HasMaxLength(2048);
            entity.HasIndex(x => x.Status);
            entity.HasIndex(x => x.Domain);
            entity.HasIndex(x => x.NextScheduleCheckAtUtc);
            entity.HasOne(x => x.AcmeProvider).WithMany().HasForeignKey(x => x.AcmeProviderId).OnDelete(DeleteBehavior.Restrict);
            entity.HasOne(x => x.AcmeAccount).WithMany().HasForeignKey(x => x.AcmeAccountId).OnDelete(DeleteBehavior.SetNull);
            entity.HasOne(x => x.VaultServer).WithMany().HasForeignKey(x => x.VaultServerId).OnDelete(DeleteBehavior.Restrict);
            entity.HasOne(x => x.DnsProvider).WithMany().HasForeignKey(x => x.DnsProviderId).OnDelete(DeleteBehavior.SetNull);
            entity.HasOne(x => x.Certificate).WithMany().HasForeignKey(x => x.CertificateId).OnDelete(DeleteBehavior.SetNull);
        });

        modelBuilder.Entity<DeploymentTarget>(entity =>
        {
            entity.Property(x => x.Name).HasMaxLength(160).IsRequired();
            entity.Property(x => x.TargetType).HasConversion<string>().HasMaxLength(60);
            entity.Property(x => x.ConfigurationJson).IsRequired();
            entity.Property(x => x.SecretReference).HasMaxLength(512);
            entity.HasIndex(x => x.Name).IsUnique();
            entity.HasIndex(x => x.IsEnabled);
            entity.HasOne(x => x.Asset).WithMany().HasForeignKey(x => x.AssetId).OnDelete(DeleteBehavior.SetNull);
            entity.HasOne(x => x.DeploymentAgent).WithMany(x => x.DeploymentTargets)
                .HasForeignKey(x => x.DeploymentAgentId).OnDelete(DeleteBehavior.SetNull);
        });

        modelBuilder.Entity<DeploymentPolicy>(entity =>
        {
            entity.Property(x => x.Name).HasMaxLength(160).IsRequired();
            entity.Property(x => x.DeploymentWindow).HasMaxLength(160);
            entity.Property(x => x.VerificationQuorumMode).HasConversion<string>().HasMaxLength(32);
            entity.HasIndex(x => x.Name).IsUnique();
            entity.HasIndex(x => x.IsEnabled);
        });

        modelBuilder.Entity<CertificateDeployment>(entity =>
        {
            entity.Property(x => x.Status).HasConversion<string>().HasMaxLength(60);
            entity.Property(x => x.Origin).HasConversion<string>().HasMaxLength(40);
            entity.Property(x => x.IdempotencyKey).HasMaxLength(512).IsRequired();
            entity.Property(x => x.PreviousFingerprint).HasMaxLength(128);
            entity.Property(x => x.ExpectedFingerprint).HasMaxLength(128).IsRequired();
            entity.Property(x => x.ObservedFingerprint).HasMaxLength(128);
            entity.Property(x => x.ErrorCode).HasMaxLength(120);
            entity.Property(x => x.ErrorMessage).HasMaxLength(2048);
            entity.Property(x => x.BackupReference).HasMaxLength(1024);
            entity.Property(x => x.ExternalResourceReference).HasMaxLength(1024);
            entity.Property(x => x.RollbackStatus).HasMaxLength(512);
            entity.Property(x => x.VerificationStatus).HasMaxLength(512);
            entity.Property(x => x.InternalVerificationStatus).HasMaxLength(1024);
            entity.Property(x => x.ExternalVerificationStatus).HasMaxLength(1024);
            entity.Property(x => x.RequestedBy).HasMaxLength(160);
            entity.Property(x => x.ApprovedBy).HasMaxLength(160);
            entity.HasIndex(x => x.IdempotencyKey).IsUnique();
            entity.HasIndex(x => new { x.DeploymentTargetId, x.CertificateId });
            entity.HasIndex(x => new { x.Status, x.CreatedAtUtc });
            entity.HasOne(x => x.CertificateRequest).WithMany().HasForeignKey(x => x.CertificateRequestId).OnDelete(DeleteBehavior.Restrict);
            entity.HasOne(x => x.Certificate).WithMany().HasForeignKey(x => x.CertificateId).OnDelete(DeleteBehavior.Restrict);
            entity.HasOne(x => x.DeploymentTarget).WithMany().HasForeignKey(x => x.DeploymentTargetId).OnDelete(DeleteBehavior.Restrict);
            entity.HasOne(x => x.DeploymentPolicy).WithMany().HasForeignKey(x => x.DeploymentPolicyId).OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<DeploymentVerificationRun>(entity =>
        {
            entity.Property(x => x.QuorumMode).HasConversion<string>().HasMaxLength(32);
            entity.Property(x => x.Outcome).HasConversion<string>().HasMaxLength(32);
            entity.Property(x => x.Summary).HasMaxLength(1024);
            entity.HasIndex(x => new { x.CertificateDeploymentId, x.Attempt });
            entity.HasOne(x => x.CertificateDeployment).WithMany(x => x.VerificationRuns)
                .HasForeignKey(x => x.CertificateDeploymentId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<DeploymentEndpointVerification>(entity =>
        {
            entity.Property(x => x.Endpoint).HasMaxLength(2048).IsRequired();
            entity.Property(x => x.ObservedAddress).HasMaxLength(128);
            entity.Property(x => x.ExpectedFingerprint).HasMaxLength(128).IsRequired();
            entity.Property(x => x.ObservedFingerprint).HasMaxLength(128);
            entity.Property(x => x.Subject).HasMaxLength(1024);
            entity.Property(x => x.Issuer).HasMaxLength(1024);
            entity.Property(x => x.Outcome).HasConversion<string>().HasMaxLength(32);
            entity.Property(x => x.ErrorCode).HasMaxLength(120);
            entity.Property(x => x.ErrorMessage).HasMaxLength(2048);
            entity.HasIndex(x => new { x.DeploymentVerificationRunId, x.ObservedAtUtc });
            entity.HasOne(x => x.DeploymentVerificationRun).WithMany(x => x.Endpoints)
                .HasForeignKey(x => x.DeploymentVerificationRunId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<DeploymentJob>(entity =>
        {
            entity.Property(x => x.IdempotencyKey).HasMaxLength(512).IsRequired();
            entity.Property(x => x.Status).HasConversion<string>().HasMaxLength(40);
            entity.Property(x => x.ClaimOwner).HasMaxLength(160);
            entity.Property(x => x.LastError).HasMaxLength(2048);
            entity.HasIndex(x => x.IdempotencyKey).IsUnique();
            entity.HasIndex(x => new { x.Status, x.NextAttemptAtUtc, x.LeaseExpiresAtUtc });
            entity.HasOne(x => x.CertificateDeployment).WithMany().HasForeignKey(x => x.CertificateDeploymentId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<DeploymentAuditEvent>(entity =>
        {
            entity.Property(x => x.EventType).HasMaxLength(80).IsRequired();
            entity.Property(x => x.Actor).HasMaxLength(160);
            entity.Property(x => x.Message).HasMaxLength(2048);
            entity.Property(x => x.Status).HasConversion<string>().HasMaxLength(60);
            entity.Property(x => x.CertificateFingerprint).HasMaxLength(128);
            entity.HasIndex(x => new { x.CertificateDeploymentId, x.CreatedAtUtc });
            entity.HasOne(x => x.CertificateDeployment).WithMany().HasForeignKey(x => x.CertificateDeploymentId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AppUser>(entity =>
        {
            entity.Property(x => x.UserName).HasMaxLength(120).IsRequired();
            entity.Property(x => x.DisplayName).HasMaxLength(160).IsRequired();
            entity.Property(x => x.PasswordHash).HasMaxLength(512).IsRequired();
            entity.Property(x => x.Role).HasMaxLength(40).IsRequired();
            entity.HasIndex(x => x.UserName).IsUnique();
        });

        modelBuilder.Entity<DiscoveryJob>(entity =>
        {
            entity.Property(x => x.Name).HasMaxLength(160).IsRequired();
            entity.Property(x => x.Cidr).HasMaxLength(64).IsRequired();
            entity.Property(x => x.Ports).HasMaxLength(256).IsRequired();
            entity.Property(x => x.Status).HasConversion<string>().HasMaxLength(40);
            entity.Property(x => x.RequestedBy).HasMaxLength(120);
            entity.HasIndex(x => x.Status);
            entity.HasIndex(x => x.RequestedAtUtc);
        });

        modelBuilder.Entity<DiscoveredEndpoint>(entity =>
        {
            entity.Property(x => x.IpAddress).HasMaxLength(64).IsRequired();
            entity.Property(x => x.ProtocolGuess).HasConversion<string>().HasMaxLength(20);
            entity.Property(x => x.Status).HasConversion<string>().HasMaxLength(40);
            entity.Property(x => x.ErrorType).HasConversion<string>().HasMaxLength(60);
            entity.HasIndex(x => x.DiscoveryJobId);
            entity.HasIndex(x => new { x.DiscoveryJobId, x.IpAddress, x.Port }).IsUnique();
            entity.HasIndex(x => x.CertificateId);
        });

        modelBuilder.Entity<VaultDiscoveryJob>(entity =>
        {
            entity.Property(x => x.Name).HasMaxLength(160).IsRequired();
            entity.Property(x => x.KvMountPath).HasMaxLength(160).IsRequired();
            entity.Property(x => x.BasePath).HasMaxLength(512).IsRequired();
            entity.Property(x => x.Status).HasConversion<string>().HasMaxLength(40);
            entity.Property(x => x.RequestedBy).HasMaxLength(120);
            entity.HasIndex(x => x.Status);
            entity.HasIndex(x => x.RequestedAtUtc);
            entity.HasOne(x => x.VaultServer).WithMany().HasForeignKey(x => x.VaultServerId).OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<VaultDiscoveryResult>(entity =>
        {
            entity.Property(x => x.SecretPath).HasMaxLength(512).IsRequired();
            entity.Property(x => x.Domain).HasMaxLength(255);
            entity.Property(x => x.SubjectAlternativeNames).HasMaxLength(2048);
            entity.Property(x => x.Status).HasConversion<string>().HasMaxLength(40);
            entity.Property(x => x.ErrorMessage).HasMaxLength(2048);
            entity.HasIndex(x => x.VaultDiscoveryJobId);
            entity.HasIndex(x => new { x.VaultDiscoveryJobId, x.SecretPath }).IsUnique();
            entity.HasIndex(x => x.CertificateId);
            entity.HasOne(x => x.VaultDiscoveryJob).WithMany(x => x.Results).HasForeignKey(x => x.VaultDiscoveryJobId).OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(x => x.Certificate).WithMany().HasForeignKey(x => x.CertificateId).OnDelete(DeleteBehavior.SetNull);
            entity.HasOne(x => x.PromotedAsset).WithMany().HasForeignKey(x => x.PromotedAssetId).OnDelete(DeleteBehavior.SetNull);
        });
    }
}
