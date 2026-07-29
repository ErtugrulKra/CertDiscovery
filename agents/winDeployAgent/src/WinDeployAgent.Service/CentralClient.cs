using System.Net.Http.Json;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using WinDeployAgent.Contracts;

namespace WinDeployAgent;

public sealed class CentralClient(
    HttpClient httpClient,
    IOptions<AgentOptions> options,
    MachineCredentialStore credentialStore,
    ILogger<CentralClient> logger)
{
    private readonly AgentOptions options = options.Value;

    public async Task<AgentIdentity> RegisterAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(options.RegistrationToken))
            return await RegisterWithExchangeAsync(cancellationToken);
        using var rsa = RSA.Create(3072);
        var request = new AgentRegisterRequest(
            options.RegistrationToken,
            options.Name,
            Environment.MachineName,
            typeof(CentralClient).Assembly.GetName().Version?.ToString() ?? "1.0.0",
            Environment.OSVersion.VersionString,
            ["MicrosoftIis", "CertificateStore", "Binding", "CentralCertificateStore"],
            rsa.ExportSubjectPublicKeyInfoPem());
        using var response = await httpClient.PostAsJsonAsync(
            new Uri(options.CentralUrl, "/api/deployment-agents/register"),
            request,
            cancellationToken);
        response.EnsureSuccessStatusCode();
        var registration = await response.Content.ReadFromJsonAsync<AgentRegisterResponse>(cancellationToken)
            ?? throw new InvalidOperationException("Central returned an invalid registration response.");
        return new(registration.AgentId, registration.AgentToken, rsa.ExportPkcs8PrivateKeyPem());
    }

    private async Task<AgentIdentity> RegisterWithExchangeAsync(CancellationToken cancellationToken)
    {
        var pending = await credentialStore.LoadPendingRegistrationAsync(cancellationToken);
        if (pending is null || pending.ExpiresAtUtc <= DateTime.UtcNow)
        {
            credentialStore.DeletePendingRegistration();
            using var rsa = RSA.Create(3072);
            var publicKey = rsa.ExportSubjectPublicKeyInfoPem();
            var request = new AgentExchangeCreateRequest(
                options.Name,
                Environment.MachineName,
                typeof(CentralClient).Assembly.GetName().Version?.ToString() ?? "1.0.0",
                Environment.OSVersion.VersionString,
                ["MicrosoftIis", "CertificateStore", "Binding", "CentralCertificateStore"],
                publicKey);
            using var response = await httpClient.PostAsJsonAsync(
                new Uri(options.CentralUrl, "/api/deployment-agents/exchanges"),
                request,
                cancellationToken);
            response.EnsureSuccessStatusCode();
            var exchange = await response.Content.ReadFromJsonAsync<AgentExchangeCreateResponse>(cancellationToken)
                ?? throw new InvalidOperationException("Central returned an invalid registration exchange.");
            var fingerprint = Convert.ToHexString(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo()));
            pending = new(
                exchange.ExchangeId,
                exchange.ExchangeSecret,
                exchange.UserCode,
                new Uri(exchange.VerificationUri),
                exchange.ExpiresAtUtc,
                Math.Clamp(exchange.PollIntervalSeconds, 3, 30),
                rsa.ExportPkcs8PrivateKeyPem(),
                fingerprint);
            await credentialStore.SavePendingRegistrationAsync(pending, cancellationToken);
        }

        logger.LogWarning(
            "Agent registration approval required. Code: {UserCode}; approve at {VerificationUri}; machine: {MachineName}; public key fingerprint: {PublicKeyFingerprint}",
            pending.UserCode,
            pending.VerificationUri,
            Environment.MachineName,
            pending.PublicKeyFingerprint);

        while (!cancellationToken.IsCancellationRequested)
        {
            if (pending.ExpiresAtUtc <= DateTime.UtcNow)
            {
                credentialStore.DeletePendingRegistration();
                throw new InvalidOperationException("Agent registration approval expired. Restart the agent to create a new request.");
            }
            using var request = new HttpRequestMessage(
                HttpMethod.Get,
                new Uri(options.CentralUrl, $"/api/deployment-agents/exchanges/{pending.ExchangeId:D}"));
            request.Headers.Add("X-Agent-Exchange-Secret", pending.ExchangeSecret);
            using var response = await httpClient.SendAsync(request, cancellationToken);
            response.EnsureSuccessStatusCode();
            var poll = await response.Content.ReadFromJsonAsync<AgentExchangePollResponse>(cancellationToken)
                ?? throw new InvalidOperationException("Central returned an invalid registration exchange status.");
            if (string.Equals(poll.Status, "Completed", StringComparison.OrdinalIgnoreCase) &&
                poll.Registration is not null)
            {
                var identity = new AgentIdentity(
                    poll.Registration.AgentId,
                    poll.Registration.AgentToken,
                    pending.PrivateKeyPem);
                await credentialStore.SaveAsync(identity, cancellationToken);
                credentialStore.DeletePendingRegistration();
                return identity;
            }
            if (string.Equals(poll.Status, "Rejected", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(poll.Status, "Expired", StringComparison.OrdinalIgnoreCase))
            {
                credentialStore.DeletePendingRegistration();
                throw new InvalidOperationException(poll.Message ?? $"Agent registration was {poll.Status.ToLowerInvariant()}.");
            }
            await Task.Delay(TimeSpan.FromSeconds(pending.PollIntervalSeconds), cancellationToken);
        }
        throw new OperationCanceledException(cancellationToken);
    }

    public async Task HeartbeatAsync(AgentIdentity identity, bool busy, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(options.CentralUrl, $"/api/deployment-agents/{identity.AgentId:D}/heartbeat"));
        request.Headers.Add("X-Deployment-Agent-Token", identity.AgentToken);
        request.Content = JsonContent.Create(new AgentHeartbeatRequest(
            typeof(CentralClient).Assembly.GetName().Version?.ToString() ?? "1.0.0",
            Environment.OSVersion.VersionString,
            ["MicrosoftIis", "CertificateStore", "Binding", "CentralCertificateStore"],
            busy));
        using var response = await httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    public async Task<AgentJobClaimResponse?> ClaimAsync(AgentIdentity identity, CancellationToken cancellationToken)
    {
        using var request = Authenticated(identity, HttpMethod.Post, $"/api/deployment-agents/{identity.AgentId:D}/jobs/claim");
        request.Content = JsonContent.Create(new { });
        using var response = await httpClient.SendAsync(request, cancellationToken);
        if (response.StatusCode == System.Net.HttpStatusCode.NoContent) return null;
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<AgentJobClaimResponse>(cancellationToken)
            ?? throw new InvalidOperationException("Central returned an invalid agent job.");
    }

    public async Task<AgentJobBundleResponse> GetBundleAsync(AgentIdentity identity, AgentJobClaimResponse job, CancellationToken cancellationToken)
    {
        using var request = Authenticated(identity, HttpMethod.Get,
            $"/api/deployment-agents/{identity.AgentId:D}/jobs/{job.JobId:D}/bundle");
        request.Headers.Add("X-Agent-Job-Lease", job.LeaseToken);
        using var response = await httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<AgentJobBundleResponse>(cancellationToken)
            ?? throw new InvalidOperationException("Central returned an invalid encrypted bundle.");
    }

    public async Task RenewLeaseAsync(AgentIdentity identity, AgentJobClaimResponse job, CancellationToken cancellationToken)
    {
        using var request = Authenticated(identity, HttpMethod.Post,
            $"/api/deployment-agents/{identity.AgentId:D}/jobs/{job.JobId:D}/renew-lease");
        request.Content = JsonContent.Create(new AgentJobLeaseRequest(job.LeaseToken));
        using var response = await httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    public async Task StageAsync(AgentIdentity identity, AgentJobClaimResponse job, string stage, string? message, CancellationToken cancellationToken)
    {
        using var request = Authenticated(identity, HttpMethod.Post,
            $"/api/deployment-agents/{identity.AgentId:D}/jobs/{job.JobId:D}/stage-result");
        request.Content = JsonContent.Create(new AgentJobStageResultRequest(job.LeaseToken, stage, message));
        using var response = await httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    public async Task CompleteAsync(AgentIdentity identity, AgentJobClaimResponse job, AgentJobCompleteRequest result, CancellationToken cancellationToken)
    {
        using var request = Authenticated(identity, HttpMethod.Post,
            $"/api/deployment-agents/{identity.AgentId:D}/jobs/{job.JobId:D}/complete");
        request.Content = JsonContent.Create(result);
        using var response = await httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    private HttpRequestMessage Authenticated(AgentIdentity identity, HttpMethod method, string path)
    {
        var request = new HttpRequestMessage(method, new Uri(options.CentralUrl, path));
        request.Headers.Add("X-Deployment-Agent-Token", identity.AgentToken);
        return request;
    }
}
