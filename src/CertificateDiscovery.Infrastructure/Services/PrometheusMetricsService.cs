namespace CertificateDiscovery.Infrastructure.Services;

using System.Globalization;
using System.Text;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

public sealed class PrometheusMetricsService(CertificateDiscoveryDbContext db, ApplicationSettingsService settings)
{
    public async Task<string> RenderAsync(CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var appSettings = await settings.GetAsync(cancellationToken);
        var certificates = await db.Certificates
            .AsNoTracking()
            .Include(x => x.ChainEntries)
            .OrderBy(x => x.FingerprintSha256)
            .ToListAsync(cancellationToken);

        var builder = new StringBuilder();
        AppendHeader(builder, "certificate_discovery_certificates_total", "Total number of discovered unique certificates.", "gauge");
        builder.Append("certificate_discovery_certificates_total ")
            .AppendLine(certificates.Count.ToString(CultureInfo.InvariantCulture));

        AppendHeader(builder, "certificate_discovery_certificate_not_after_timestamp_seconds", "Certificate NotAfter value as Unix timestamp seconds.", "gauge");
        foreach (var certificate in certificates)
        {
            builder.Append("certificate_discovery_certificate_not_after_timestamp_seconds")
                .Append(CertificateLabels(certificate))
                .Append(' ')
                .AppendLine(new DateTimeOffset(certificate.NotAfterUtc).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));
        }

        AppendHeader(builder, "certificate_discovery_certificate_expires_in_days", "Remaining whole days until certificate expiration. Negative values mean expired.", "gauge");
        foreach (var certificate in certificates)
        {
            builder.Append("certificate_discovery_certificate_expires_in_days")
                .Append(CertificateLabels(certificate))
                .Append(' ')
                .AppendLine(CertificateStatusCalculator.RemainingDays(certificate.NotAfterUtc, now).ToString(CultureInfo.InvariantCulture));
        }

        AppendHeader(builder, "certificate_discovery_certificate_expired", "Whether the certificate is expired. 1 means expired, 0 means not expired.", "gauge");
        foreach (var certificate in certificates)
        {
            var expired = CertificateStatusCalculator.RemainingDays(certificate.NotAfterUtc, now) < 0 ? 1 : 0;
            builder.Append("certificate_discovery_certificate_expired")
                .Append(CertificateLabels(certificate))
                .Append(' ')
                .AppendLine(expired.ToString(CultureInfo.InvariantCulture));
        }

        AppendHeader(builder, "certificate_discovery_certificate_chain_entries", "Number of stored chain entries for the certificate.", "gauge");
        foreach (var certificate in certificates)
        {
            builder.Append("certificate_discovery_certificate_chain_entries")
                .Append(CertificateLabels(certificate))
                .Append(' ')
                .AppendLine(certificate.ChainEntries.Count.ToString(CultureInfo.InvariantCulture));
        }

        AppendHeader(builder, "certificate_discovery_certificate_status_total", "Certificate count by calculated expiration status.", "gauge");
        foreach (var group in certificates
                     .GroupBy(x => CertificateStatusCalculator.GetStatus(x.NotAfterUtc, now, appSettings.ExpireCriticalDays, appSettings.ExpireWarningDays, appSettings.ExpireAttentionDays))
                     .OrderBy(x => x.Key.ToString()))
        {
            builder.Append("certificate_discovery_certificate_status_total")
                .Append(LabelSet(("status", group.Key.ToString())))
                .Append(' ')
                .AppendLine(group.Count().ToString(CultureInfo.InvariantCulture));
        }

        return builder.ToString();
    }

    private static void AppendHeader(StringBuilder builder, string name, string help, string type)
    {
        builder.Append("# HELP ").Append(name).Append(' ').AppendLine(help);
        builder.Append("# TYPE ").Append(name).Append(' ').AppendLine(type);
    }

    private static string CertificateLabels(Domain.Entities.Certificate certificate) =>
        LabelSet(
            ("fingerprint_sha256", certificate.FingerprintSha256),
            ("common_name", certificate.CommonName ?? ""),
            ("issuer", certificate.Issuer),
            ("source", certificate.Source.ToString()),
            ("source_name", certificate.SourceName ?? ""),
            ("is_self_signed", certificate.IsSelfSigned ? "true" : "false"));

    private static string LabelSet(params (string Key, string Value)[] labels) =>
        "{" + string.Join(",", labels.Select(x => $"{x.Key}=\"{EscapeLabelValue(x.Value)}\"")) + "}";

    private static string EscapeLabelValue(string value) =>
        value.Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal);
}
