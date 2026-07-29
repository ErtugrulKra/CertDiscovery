namespace CertificateDiscovery.Infrastructure.Services;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Infrastructure.Mapping;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

public sealed class CertificateService(CertificateDiscoveryDbContext db, ApplicationSettingsService settings)
{
    public async Task<List<CertificateSummaryDto>> ListAsync(CancellationToken cancellationToken)
    {
        var appSettings = await settings.GetAsync(cancellationToken);
        var certificates = await db.Certificates
            .Include(x => x.AssetCertificates)
            .OrderBy(x => x.NotAfterUtc)
            .ToListAsync(cancellationToken);
        return certificates.Select(x => DtoMapper.ToSummary(x, null, appSettings.ExpireCriticalDays, appSettings.ExpireWarningDays, appSettings.ExpireAttentionDays)).ToList();
    }

    public async Task<CertificateDetailDto?> GetAsync(Guid id, CancellationToken cancellationToken)
    {
        var appSettings = await settings.GetAsync(cancellationToken);
        var certificate = await db.Certificates
            .Include(x => x.SubjectAlternativeNames)
            .Include(x => x.ChainEntries)
            .Include(x => x.AssetCertificates).ThenInclude(x => x.Asset)
            .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

        if (certificate is null) return null;
        var kubernetesSources = await db.KubernetesCertificateSources
            .AsNoTracking()
            .Where(x => x.CertificateId == id)
            .Include(x => x.KubernetesCluster)
            .OrderBy(x => x.KubernetesCluster.Name)
            .ThenBy(x => x.Namespace)
            .ThenBy(x => x.SecretName)
            .Select(x => new KubernetesCertificateSourceDto(
                x.KubernetesCluster.Name, x.Namespace, x.SecretName, x.FirstSeenAtUtc, x.LastSeenAtUtc))
            .ToListAsync(cancellationToken);
        var summary = DtoMapper.ToSummary(certificate, null, appSettings.ExpireCriticalDays, appSettings.ExpireWarningDays, appSettings.ExpireAttentionDays);
        return new CertificateDetailDto(
            certificate.Id,
            certificate.FingerprintSha256,
            certificate.SerialNumber,
            certificate.Subject,
            certificate.CommonName,
            certificate.Issuer,
            certificate.NotBeforeUtc,
            certificate.NotAfterUtc,
            summary.RemainingDays,
            summary.Status,
            certificate.SignatureAlgorithm,
            certificate.PublicKeyAlgorithm,
            certificate.PublicKeySize,
            certificate.Version,
            certificate.IsSelfSigned,
            certificate.Source,
            certificate.SourceName,
            certificate.ExternalReference,
            certificate.CreatedAtUtc,
            certificate.LastSeenAtUtc,
            certificate.ChainEntries
                .OrderBy(x => x.Position)
                .Select(x => new CertificateChainEntryDto(
                    x.Position,
                    x.FingerprintSha256,
                    x.SerialNumber,
                    x.Subject,
                    x.CommonName,
                    x.Issuer,
                    x.NotBeforeUtc,
                    x.NotAfterUtc,
                    x.SignatureAlgorithm,
                    x.PublicKeyAlgorithm,
                    x.PublicKeySize,
                    x.Version,
                    x.IsSelfSigned,
                    x.LastSeenAtUtc))
                .ToList(),
            certificate.SubjectAlternativeNames.Select(x => new SubjectAlternativeNameDto(x.Name, x.Type)).OrderBy(x => x.Name).ToList(),
            certificate.AssetCertificates.Select(x => new CertificateAssetUsageDto(
                x.AssetId,
                x.Asset.Name,
                x.Asset.Host,
                x.Asset.Port,
                x.Asset.Protocol,
                x.Asset.Environment,
                x.Asset.Owner,
                x.FirstSeenAtUtc,
                x.LastSeenAtUtc,
                x.IsCurrentlyActive)).OrderBy(x => x.AssetName).ToList(),
            kubernetesSources);
    }
}
