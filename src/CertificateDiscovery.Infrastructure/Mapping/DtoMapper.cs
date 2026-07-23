namespace CertificateDiscovery.Infrastructure.Mapping;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;

public static class DtoMapper
{
    public static CertificateSummaryDto ToSummary(Certificate certificate, DateTime? nowUtc = null, int criticalDays = 7, int warningDays = 30, int attentionDays = 60)
    {
        var assets = certificate.AssetCertificates.Count(x => x.IsCurrentlyActive);
        return new CertificateSummaryDto(
            certificate.Id,
            certificate.FingerprintSha256,
            certificate.CommonName,
            certificate.Subject,
            certificate.Issuer,
            certificate.NotBeforeUtc,
            certificate.NotAfterUtc,
            CertificateStatusCalculator.RemainingDays(certificate.NotAfterUtc, nowUtc),
            CertificateStatusCalculator.GetStatus(certificate.NotAfterUtc, nowUtc, criticalDays, warningDays, attentionDays),
            certificate.IsSelfSigned,
            certificate.Source,
            certificate.SourceName,
            assets,
            certificate.LastSeenAtUtc);
    }

    public static AssetDto ToDto(Asset asset)
    {
        var active = asset.AssetCertificates.FirstOrDefault(x => x.IsCurrentlyActive)?.Certificate;
        var lastResult = asset.ScanResults.OrderByDescending(x => x.CompletedAtUtc).FirstOrDefault();
        return new AssetDto(
            asset.Id,
            asset.Name,
            asset.Description,
            asset.Host,
            asset.Port,
            asset.Protocol,
            asset.Path,
            asset.SniHost,
            asset.Environment,
            asset.AssetType,
            asset.Owner,
            asset.IsEnabled,
            asset.ScanIntervalMinutes,
            asset.TimeoutSeconds,
            asset.Tags,
            asset.CreatedAtUtc,
            asset.UpdatedAtUtc,
            asset.LastScanAtUtc,
            asset.NextScanAtUtc,
            lastResult?.Status.ToString(),
            active is null ? null : ToSummary(active));
    }
}
