using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertificateDiscovery.Infrastructure.Deployment;

public interface ITlsEndpointVerifier
{
    Task<(bool Succeeded, string? ObservedFingerprint, string Message)> VerifyAsync(
        IReadOnlyList<Uri> endpoints,
        string expectedFingerprint,
        CancellationToken cancellationToken);
}

public sealed class TlsEndpointVerifier : ITlsEndpointVerifier
{
    public async Task<(bool Succeeded, string? ObservedFingerprint, string Message)> VerifyAsync(
        IReadOnlyList<Uri> endpoints,
        string expectedFingerprint,
        CancellationToken cancellationToken)
    {
        string? last = null;
        foreach (var endpoint in endpoints)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(15));
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(endpoint.Host, endpoint.IsDefaultPort ? 443 : endpoint.Port, timeout.Token);
            X509Certificate2? observedCertificate = null;
            using var tls = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = endpoint.Host,
                RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                {
                    if (certificate is not null)
                        observedCertificate = new X509Certificate2(certificate);
                    return true;
                }
            }, timeout.Token);
            if (observedCertificate is null)
                return (false, null, $"Endpoint '{endpoint}' did not return a certificate.");
            using (observedCertificate)
                last = Convert.ToHexString(SHA256.HashData(observedCertificate.RawData));
            if (!string.Equals(last, expectedFingerprint, StringComparison.OrdinalIgnoreCase))
                return (false, last, $"Endpoint '{endpoint}' serves a different certificate fingerprint.");
        }
        return (true, last ?? expectedFingerprint, $"{endpoints.Count} external TLS endpoint(s) verified.");
    }
}
