using System.Diagnostics;
using System.Formats.Asn1;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using CertificateDiscovery.Application.Deployment;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Infrastructure.Deployment;

public sealed record PublicCertificateChainEntry(
    int Position, string Subject, string Issuer, string FingerprintSha256,
    DateTime NotBeforeUtc, DateTime NotAfterUtc);

public sealed record TlsCertificateObservation(
    Uri Endpoint, string? ObservedAddress, string? Fingerprint, string? Subject, string? Issuer,
    DateTime? NotBeforeUtc, DateTime? NotAfterUtc, IReadOnlyList<string> SubjectAlternativeNames,
    IReadOnlyList<PublicCertificateChainEntry> PublicChain, bool ChainValid,
    string? ErrorCode, string? ErrorMessage, long DurationMilliseconds);

public interface ITlsCertificateProbe
{
    Task<TlsCertificateObservation> ProbeAsync(Uri endpoint, CancellationToken cancellationToken);
}

public interface ITlsEndpointVerifier
{
    Task<(bool Succeeded, string? ObservedFingerprint, string Message)> VerifyAsync(
        IReadOnlyList<Uri> endpoints, string expectedFingerprint, CancellationToken cancellationToken);
}

public interface IMultiNodeTlsVerifier
{
    Task<(VerificationQuorumResult Quorum, IReadOnlyList<DeploymentEndpointVerification> Endpoints)> VerifyAsync(
        IReadOnlyList<Uri> endpoints,
        string expectedFingerprint,
        DeploymentPolicy policy,
        CancellationToken cancellationToken);
}

public sealed class TlsCertificateProbe : ITlsCertificateProbe
{
    public async Task<TlsCertificateObservation> ProbeAsync(Uri endpoint, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(15));
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(endpoint.Host, endpoint.IsDefaultPort ? 443 : endpoint.Port, timeout.Token);
            X509Certificate2? observed = null;
            var chainEntries = new List<X509Certificate2>();
            SslPolicyErrors policyErrors = SslPolicyErrors.None;
            using var tls = new SslStream(tcp.GetStream(), false, (_, certificate, chain, errors) =>
            {
                policyErrors = errors;
                if (certificate is not null) observed = new X509Certificate2(certificate);
                if (chain is not null)
                    chainEntries.AddRange(chain.ChainElements.Cast<X509ChainElement>()
                        .Select(x => new X509Certificate2(x.Certificate)));
                return true;
            });
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = endpoint.Host,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            }, timeout.Token);
            if (observed is null)
                return Failure(endpoint, "CertificateMissing", "The endpoint did not return a certificate.", stopwatch.ElapsedMilliseconds);
            using (observed)
            {
                if (chainEntries.Count == 0) chainEntries.Add(new X509Certificate2(observed));
                try
                {
                    return new(endpoint,
                        (tcp.Client.RemoteEndPoint as IPEndPoint)?.Address.ToString(),
                        Fingerprint(observed), observed.Subject, observed.Issuer,
                        observed.NotBefore.ToUniversalTime(), observed.NotAfter.ToUniversalTime(),
                        DnsSubjectAlternativeNames(observed),
                        chainEntries.Select((certificate, position) => new PublicCertificateChainEntry(
                            position, certificate.Subject, certificate.Issuer, Fingerprint(certificate),
                            certificate.NotBefore.ToUniversalTime(), certificate.NotAfter.ToUniversalTime())).ToList(),
                        (policyErrors & SslPolicyErrors.RemoteCertificateChainErrors) == 0,
                        null, null, stopwatch.ElapsedMilliseconds);
                }
                finally
                {
                    foreach (var certificate in chainEntries) certificate.Dispose();
                }
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Failure(endpoint, "ConnectionTimeout", "TLS endpoint verification timed out.", stopwatch.ElapsedMilliseconds);
        }
        catch (SocketException)
        {
            return Failure(endpoint, "ConnectionFailed", "TLS endpoint connection failed.", stopwatch.ElapsedMilliseconds);
        }
        catch (AuthenticationException)
        {
            return Failure(endpoint, "TlsHandshakeFailed", "TLS endpoint handshake failed.", stopwatch.ElapsedMilliseconds);
        }
    }

    private static TlsCertificateObservation Failure(Uri endpoint, string code, string message, long duration) =>
        new(endpoint, null, null, null, null, null, null, [], [], false, code, message, duration);
    private static string Fingerprint(X509Certificate2 certificate) =>
        Convert.ToHexString(SHA256.HashData(certificate.RawData));

    internal static IReadOnlyList<string> DnsSubjectAlternativeNames(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions["2.5.29.17"];
        if (extension is null) return [];
        try
        {
            var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER);
            var sequence = reader.ReadSequence();
            var values = new List<string>();
            var dnsTag = new Asn1Tag(TagClass.ContextSpecific, 2);
            while (sequence.HasData)
            {
                if (sequence.PeekTag().HasSameClassAndValue(dnsTag))
                    values.Add(sequence.ReadCharacterString(UniversalTagNumber.IA5String, dnsTag));
                else
                    _ = sequence.ReadEncodedValue();
            }
            return values;
        }
        catch (AsnContentException)
        {
            return [];
        }
    }
}

public sealed class TlsEndpointVerifier(ITlsCertificateProbe probe) : ITlsEndpointVerifier, IMultiNodeTlsVerifier
{
    public TlsEndpointVerifier() : this(new TlsCertificateProbe()) { }

    public async Task<(bool Succeeded, string? ObservedFingerprint, string Message)> VerifyAsync(
        IReadOnlyList<Uri> endpoints, string expectedFingerprint, CancellationToken cancellationToken)
    {
        var policy = new DeploymentPolicy();
        var result = await VerifyAsync(endpoints, expectedFingerprint, policy, cancellationToken);
        var last = result.Endpoints.LastOrDefault()?.ObservedFingerprint;
        return (result.Quorum.Outcome == DeploymentVerificationOutcome.Verified, last, result.Quorum.Message);
    }

    public async Task<(VerificationQuorumResult Quorum, IReadOnlyList<DeploymentEndpointVerification> Endpoints)> VerifyAsync(
        IReadOnlyList<Uri> endpoints, string expectedFingerprint, DeploymentPolicy policy, CancellationToken cancellationToken)
    {
        var results = new List<DeploymentEndpointVerification>();
        VerificationQuorumResult? lastQuorum = null;
        for (var attempt = 0; attempt < policy.VerificationAttempts; attempt++)
        {
            var currentAttempt = new List<DeploymentEndpointVerification>();
            foreach (var endpoint in endpoints)
                currentAttempt.Add(ToEntity(await probe.ProbeAsync(endpoint, cancellationToken), expectedFingerprint));
            results.AddRange(currentAttempt);
            lastQuorum = Evaluate(currentAttempt, policy, expectedFingerprint);
            if (lastQuorum.Outcome == DeploymentVerificationOutcome.Verified) return (lastQuorum, results);
            if (attempt + 1 < policy.VerificationAttempts)
                await Task.Delay(TimeSpan.FromSeconds(policy.VerificationIntervalSeconds), cancellationToken);
        }
        return (lastQuorum ?? Evaluate(results, policy, expectedFingerprint), results);
    }

    private static VerificationQuorumResult Evaluate(
        IReadOnlyCollection<DeploymentEndpointVerification> results, DeploymentPolicy policy, string expected) =>
        VerificationQuorumEvaluator.Evaluate(
            results.Select(x => new VerificationNodeResult(x.Outcome == EndpointVerificationOutcome.Verified, x.ObservedFingerprint)).ToList(),
            policy.VerificationQuorumMode, policy.VerificationQuorumPercentage,
            policy.VerificationMinimumSuccessfulNodes, expected);

    private static DeploymentEndpointVerification ToEntity(TlsCertificateObservation observation, string expected)
    {
        var now = DateTime.UtcNow;
        var fingerprintMatches = string.Equals(observation.Fingerprint, expected, StringComparison.OrdinalIgnoreCase);
        var sanMatches = MatchesDnsName(observation.Endpoint.Host, observation.SubjectAlternativeNames);
        var timeValid = observation.NotBeforeUtc <= now && observation.NotAfterUtc > now;
        var outcome = observation.ErrorCode is not null ? EndpointVerificationOutcome.Unreachable
            : !fingerprintMatches ? EndpointVerificationOutcome.FingerprintMismatch
            : !sanMatches ? EndpointVerificationOutcome.SanMismatch
            : observation.NotBeforeUtc > now ? EndpointVerificationOutcome.NotYetValid
            : observation.NotAfterUtc <= now ? EndpointVerificationOutcome.Expired
            : !observation.ChainValid ? EndpointVerificationOutcome.ChainInvalid
            : EndpointVerificationOutcome.Verified;
        return new()
        {
            Endpoint = observation.Endpoint.ToString(), ObservedAddress = observation.ObservedAddress,
            ExpectedFingerprint = expected, ObservedFingerprint = observation.Fingerprint,
            Subject = observation.Subject, Issuer = observation.Issuer,
            NotBeforeUtc = observation.NotBeforeUtc, NotAfterUtc = observation.NotAfterUtc,
            SubjectAlternativeNamesJson = System.Text.Json.JsonSerializer.Serialize(observation.SubjectAlternativeNames),
            FingerprintMatches = fingerprintMatches, SanMatches = sanMatches, TimeValid = timeValid,
            ChainValid = observation.ChainValid,
            PublicChainJson = System.Text.Json.JsonSerializer.Serialize(observation.PublicChain),
            Outcome = outcome, ErrorCode = observation.ErrorCode, ErrorMessage = observation.ErrorMessage,
            DurationMilliseconds = observation.DurationMilliseconds, ObservedAtUtc = now
        };
    }

    internal static bool MatchesDnsName(string host, IReadOnlyList<string> names)
    {
        if (IPAddress.TryParse(host, out _))
            return names.Contains(host, StringComparer.OrdinalIgnoreCase);
        return names.Any(name =>
            string.Equals(name, host, StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith("*.", StringComparison.Ordinal) &&
            host.EndsWith(name[1..], StringComparison.OrdinalIgnoreCase) &&
            host.Count(x => x == '.') == name.Count(x => x == '.'));
    }
}
