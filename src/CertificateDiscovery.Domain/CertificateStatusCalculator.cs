namespace CertificateDiscovery.Domain;

public static class CertificateStatusCalculator
{
    public static int RemainingDays(DateTime notAfterUtc, DateTime? nowUtc = null)
    {
        var today = (nowUtc ?? DateTime.UtcNow).Date;
        return (int)Math.Floor((notAfterUtc.Date - today).TotalDays);
    }

    public static CertificateHealthStatus GetStatus(DateTime notAfterUtc, DateTime? nowUtc = null, int criticalDays = 7, int warningDays = 30, int attentionDays = 60)
    {
        var days = RemainingDays(notAfterUtc, nowUtc);
        return days < 0 ? CertificateHealthStatus.Expired :
            days <= criticalDays ? CertificateHealthStatus.Critical :
            days <= warningDays ? CertificateHealthStatus.Warning :
            days <= attentionDays ? CertificateHealthStatus.Attention :
            CertificateHealthStatus.Healthy;
    }
}
