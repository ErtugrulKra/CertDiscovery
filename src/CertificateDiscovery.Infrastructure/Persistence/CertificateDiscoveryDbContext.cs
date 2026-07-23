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

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
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
            entity.Property(x => x.Notes).HasMaxLength(1024);
            entity.HasIndex(x => x.Name).IsUnique();
            entity.HasIndex(x => x.IsEnabled);
        });

        modelBuilder.Entity<DnsProvider>(entity =>
        {
            entity.Property(x => x.Name).HasMaxLength(160).IsRequired();
            entity.Property(x => x.ProviderType).HasConversion<string>().HasMaxLength(60);
            entity.Property(x => x.ZoneName).HasMaxLength(255).IsRequired();
            entity.Property(x => x.ApiToken).HasMaxLength(2048);
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
            entity.HasOne(x => x.VaultServer).WithMany().HasForeignKey(x => x.VaultServerId).OnDelete(DeleteBehavior.Restrict);
            entity.HasOne(x => x.DnsProvider).WithMany().HasForeignKey(x => x.DnsProviderId).OnDelete(DeleteBehavior.SetNull);
            entity.HasOne(x => x.Certificate).WithMany().HasForeignKey(x => x.CertificateId).OnDelete(DeleteBehavior.SetNull);
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
