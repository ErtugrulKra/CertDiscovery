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
        var deployments = await db.CertificateDeployments.AsNoTracking()
            .Include(x => x.DeploymentTarget)
            .OrderBy(x => x.CreatedAtUtc)
            .ToListAsync(cancellationToken);
        var verificationRuns = await db.DeploymentVerificationRuns.AsNoTracking()
            .Include(x => x.CertificateDeployment).ThenInclude(x => x.DeploymentTarget)
            .ToListAsync(cancellationToken);
        var deploymentEvents = await db.DeploymentAuditEvents.AsNoTracking()
            .Include(x => x.CertificateDeployment).ThenInclude(x => x.DeploymentTarget)
            .OrderBy(x => x.CertificateDeploymentId).ThenBy(x => x.CreatedAtUtc)
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

        AppendHeader(builder, "certificate_discovery_deployments_total",
            "Deployment count by terminal or active status and target type.", "counter");
        foreach (var group in deployments.GroupBy(x => new { x.Status, x.DeploymentTarget.TargetType })
                     .OrderBy(x => x.Key.TargetType).ThenBy(x => x.Key.Status))
            Metric(builder, "certificate_discovery_deployments_total", group.Count(),
                ("status", group.Key.Status.ToString()), ("target_type", group.Key.TargetType.ToString()));

        AppendHeader(builder, "certificate_discovery_deployment_retries_total",
            "Total deployment retry attempts by target type.", "counter");
        foreach (var group in deployments.GroupBy(x => x.DeploymentTarget.TargetType).OrderBy(x => x.Key))
            Metric(builder, "certificate_discovery_deployment_retries_total",
                group.Sum(x => Math.Max(0, x.Attempt - 1)), ("target_type", group.Key.ToString()));

        AppendHeader(builder, "certificate_discovery_deployment_rollbacks_total",
            "Rollback outcomes by target type.", "counter");
        foreach (var group in deployments
                     .Where(x => x.Status is CertificateDeploymentStatus.RolledBack or CertificateDeploymentStatus.RollbackFailed)
                     .GroupBy(x => new { x.DeploymentTarget.TargetType, x.Status })
                     .OrderBy(x => x.Key.TargetType).ThenBy(x => x.Key.Status))
            Metric(builder, "certificate_discovery_deployment_rollbacks_total", group.Count(),
                ("target_type", group.Key.TargetType.ToString()), ("outcome", group.Key.Status.ToString()));

        AppendHeader(builder, "certificate_discovery_deployment_verifications_total",
            "External deployment verification runs by target type and outcome.", "counter");
        foreach (var group in verificationRuns
                     .GroupBy(x => new { x.CertificateDeployment.DeploymentTarget.TargetType, x.Outcome })
                     .OrderBy(x => x.Key.TargetType).ThenBy(x => x.Key.Outcome))
            Metric(builder, "certificate_discovery_deployment_verifications_total", group.Count(),
                ("target_type", group.Key.TargetType.ToString()), ("outcome", group.Key.Outcome.ToString()));

        AppendHeader(builder, "certificate_discovery_deployment_duration_seconds_sum",
            "Accumulated completed deployment duration in seconds.", "counter");
        AppendHeader(builder, "certificate_discovery_deployment_duration_seconds_count",
            "Completed deployment duration sample count.", "counter");
        foreach (var group in deployments.Where(x => x.StartedAtUtc is not null && x.CompletedAtUtc is not null)
                     .GroupBy(x => new { x.Status, x.DeploymentTarget.TargetType })
                     .OrderBy(x => x.Key.TargetType).ThenBy(x => x.Key.Status))
        {
            var labels = new[] { ("status", group.Key.Status.ToString()), ("target_type", group.Key.TargetType.ToString()) };
            Metric(builder, "certificate_discovery_deployment_duration_seconds_sum",
                group.Sum(x => (x.CompletedAtUtc!.Value - x.StartedAtUtc!.Value).TotalSeconds), labels);
            Metric(builder, "certificate_discovery_deployment_duration_seconds_count", group.Count(), labels);
        }

        AppendStageDurationMetrics(builder, deploymentEvents);

        return builder.ToString();
    }

    private static void AppendStageDurationMetrics(
        StringBuilder builder,
        IReadOnlyList<Domain.Entities.DeploymentAuditEvent> events)
    {
        var samples = events.GroupBy(x => x.CertificateDeploymentId).SelectMany(group =>
        {
            var ordered = group.OrderBy(x => x.CreatedAtUtc).ToList();
            return ordered.Skip(1).Select((current, index) => new
            {
                Stage = SafeStage(ordered[index].EventType),
                TargetType = current.CertificateDeployment.DeploymentTarget.TargetType,
                DurationSeconds = Math.Max(0, (current.CreatedAtUtc - ordered[index].CreatedAtUtc).TotalSeconds)
            });
        }).Where(x => x.Stage is not null).ToList();
        AppendHeader(builder, "certificate_discovery_deployment_stage_duration_seconds_sum",
            "Accumulated deployment stage duration in seconds.", "counter");
        AppendHeader(builder, "certificate_discovery_deployment_stage_duration_seconds_count",
            "Observed deployment stage duration sample count.", "counter");
        foreach (var group in samples.GroupBy(x => new { x.Stage, x.TargetType })
                     .OrderBy(x => x.Key.TargetType).ThenBy(x => x.Key.Stage))
        {
            var labels = new[] { ("stage", group.Key.Stage!), ("target_type", group.Key.TargetType.ToString()) };
            Metric(builder, "certificate_discovery_deployment_stage_duration_seconds_sum",
                group.Sum(x => x.DurationSeconds), labels);
            Metric(builder, "certificate_discovery_deployment_stage_duration_seconds_count",
                group.Count(), labels);
        }
    }

    private static string? SafeStage(string eventType) => eventType switch
    {
        "Prechecking" or "BackingUp" or "Deploying" or "Activating" or "Verifying" or
        "Succeeded" or "Failed" or "RollingBack" or "RolledBack" or "RollbackFailed" or
        "PartiallyVerified" => eventType,
        _ => null
    };

    private static void Metric(
        StringBuilder builder,
        string name,
        double value,
        params (string Key, string Value)[] labels) =>
        builder.Append(name).Append(LabelSet(labels)).Append(' ')
            .AppendLine(value.ToString("0.################", CultureInfo.InvariantCulture));

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
