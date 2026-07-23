namespace CertificateDiscovery.UnitTests;

using CertificateDiscovery.Domain;

public sealed class CertificateStatusCalculatorTests
{
    [Fact]
    public void RemainingDays_UsesUtcDates()
    {
        var now = new DateTime(2026, 7, 15, 12, 0, 0, DateTimeKind.Utc);
        var notAfter = new DateTime(2026, 7, 22, 1, 0, 0, DateTimeKind.Utc);

        Assert.Equal(7, CertificateStatusCalculator.RemainingDays(notAfter, now));
        Assert.Equal(CertificateHealthStatus.Critical, CertificateStatusCalculator.GetStatus(notAfter, now));
    }

    [Theory]
    [InlineData(-1, CertificateHealthStatus.Expired)]
    [InlineData(7, CertificateHealthStatus.Critical)]
    [InlineData(30, CertificateHealthStatus.Warning)]
    [InlineData(60, CertificateHealthStatus.Attention)]
    [InlineData(61, CertificateHealthStatus.Healthy)]
    public void Status_MatchesThresholds(int days, CertificateHealthStatus expected)
    {
        var now = new DateTime(2026, 7, 15, 0, 0, 0, DateTimeKind.Utc);

        Assert.Equal(expected, CertificateStatusCalculator.GetStatus(now.AddDays(days), now));
    }
}
