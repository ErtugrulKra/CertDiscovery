using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CertificateDiscovery.Infrastructure.Services;

public sealed class DeploymentAgentService(CertificateDiscoveryDbContext db)
{
    private const int ExchangeLifetimeMinutes = 10;
    private const string UserCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    public async Task<DeploymentAgentRegistrationTokenResponse> CreateRegistrationTokenAsync(
        DeploymentAgentRegistrationTokenRequest request,
        string actor,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Description))
            throw new ArgumentException("Registration token description is required.");
        if (request.LifetimeMinutes is < 1 or > 60)
            throw new ArgumentException("Registration token lifetime must be between 1 and 60 minutes.");
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
        var expires = DateTime.UtcNow.AddMinutes(request.LifetimeMinutes);
        db.DeploymentAgentRegistrationTokens.Add(new()
        {
            TokenHash = Hash(token),
            Description = request.Description.Trim(),
            ExpiresAtUtc = expires,
            CreatedBy = actor
        });
        await db.SaveChangesAsync(cancellationToken);
        return new(token, expires);
    }

    public async Task<DeploymentAgentRegisterResponse> RegisterAsync(
        DeploymentAgentRegisterRequest request,
        CancellationToken cancellationToken)
    {
        ValidateRegistration(request);
        var now = DateTime.UtcNow;
        var tokenHash = Hash(request.RegistrationToken);
        var registration = await db.DeploymentAgentRegistrationTokens
            .FirstOrDefaultAsync(x => x.TokenHash == tokenHash, cancellationToken)
            ?? throw new UnauthorizedAccessException("Registration token is invalid.");
        if (registration.UsedAtUtc is not null || registration.ExpiresAtUtc <= now)
            throw new UnauthorizedAccessException("Registration token is expired or has already been used.");

        var agentToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        var agent = new DeploymentAgent
        {
            Name = request.Name.Trim(),
            MachineName = request.MachineName.Trim(),
            Version = request.Version.Trim(),
            OperatingSystem = request.OperatingSystem.Trim(),
            CapabilitiesJson = JsonSerializer.Serialize(NormalizeCapabilities(request.Capabilities)),
            AuthenticationTokenHash = Hash(agentToken),
            PublicKeyPem = Normalize(request.PublicKeyPem),
            Status = DeploymentAgentStatus.Online,
            LastHeartbeatAtUtc = now,
            RegisteredAtUtc = now
        };
        db.DeploymentAgents.Add(agent);
        registration.UsedAtUtc = now;
        registration.RegisteredAgentId = agent.Id;
        await db.SaveChangesAsync(cancellationToken);
        return new(agent.Id, agentToken, now);
    }

    public async Task<(DeploymentAgentExchangeCreateResponse Response, string PublicKeyFingerprint)> BeginExchangeAsync(
        DeploymentAgentExchangeCreateRequest request,
        string verificationUri,
        CancellationToken cancellationToken)
    {
        ValidateExchange(request);
        var secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
        var userCode = await CreateUniqueUserCodeAsync(cancellationToken);
        var fingerprint = PublicKeyFingerprint(request.PublicKeyPem);
        var expires = DateTime.UtcNow.AddMinutes(ExchangeLifetimeMinutes);
        var exchange = new DeploymentAgentRegistrationExchange
        {
            ExchangeSecretHash = Hash(secret),
            UserCode = userCode,
            Name = request.Name.Trim(),
            MachineName = request.MachineName.Trim(),
            Version = request.Version.Trim(),
            OperatingSystem = request.OperatingSystem.Trim(),
            CapabilitiesJson = JsonSerializer.Serialize(NormalizeCapabilities(request.Capabilities)),
            PublicKeyPem = request.PublicKeyPem.Trim(),
            PublicKeyFingerprint = fingerprint,
            ExpiresAtUtc = expires
        };
        db.DeploymentAgentRegistrationExchanges.Add(exchange);
        await db.SaveChangesAsync(cancellationToken);
        return (new(exchange.Id, secret, userCode, expires, verificationUri, 5), fingerprint);
    }

    public async Task<DeploymentAgentExchangePollResponse> PollExchangeAsync(
        Guid exchangeId,
        string? exchangeSecret,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(exchangeSecret))
            throw new UnauthorizedAccessException("Exchange secret is required.");
        var exchange = await db.DeploymentAgentRegistrationExchanges.AsNoTracking()
            .FirstOrDefaultAsync(x => x.Id == exchangeId, cancellationToken)
            ?? throw new UnauthorizedAccessException("Registration exchange is invalid.");
        if (!FixedHashEquals(exchange.ExchangeSecretHash, Hash(exchangeSecret)))
            throw new UnauthorizedAccessException("Registration exchange is invalid.");
        var now = DateTime.UtcNow;
        if (exchange.Status is DeploymentAgentExchangeStatus.Pending or DeploymentAgentExchangeStatus.Approved &&
            exchange.ExpiresAtUtc <= now)
        {
            await db.DeploymentAgentRegistrationExchanges
                .Where(x => x.Id == exchangeId &&
                            (x.Status == DeploymentAgentExchangeStatus.Pending || x.Status == DeploymentAgentExchangeStatus.Approved))
                .ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, DeploymentAgentExchangeStatus.Expired), cancellationToken);
            return new("Expired", Message: "Registration approval expired.");
        }
        if (exchange.Status != DeploymentAgentExchangeStatus.Approved)
            return new(exchange.Status.ToString(), Message: ExchangeMessage(exchange.Status));

        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        var claimed = await db.DeploymentAgentRegistrationExchanges
            .Where(x => x.Id == exchangeId && x.Status == DeploymentAgentExchangeStatus.Approved && x.ExpiresAtUtc > now)
            .ExecuteUpdateAsync(update => update
                .SetProperty(x => x.Status, DeploymentAgentExchangeStatus.Completed)
                .SetProperty(x => x.CompletedAtUtc, now), cancellationToken);
        if (claimed != 1)
        {
            await transaction.RollbackAsync(cancellationToken);
            return new("Completed", Message: "Registration exchange has already been consumed.");
        }

        var agentToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        var agent = new DeploymentAgent
        {
            Name = exchange.Name,
            MachineName = exchange.MachineName,
            Version = exchange.Version,
            OperatingSystem = exchange.OperatingSystem,
            CapabilitiesJson = exchange.CapabilitiesJson,
            AuthenticationTokenHash = Hash(agentToken),
            PublicKeyPem = exchange.PublicKeyPem,
            Status = DeploymentAgentStatus.Online,
            LastHeartbeatAtUtc = now,
            RegisteredAtUtc = now
        };
        db.DeploymentAgents.Add(agent);
        await db.SaveChangesAsync(cancellationToken);
        await db.DeploymentAgentRegistrationExchanges.Where(x => x.Id == exchangeId)
            .ExecuteUpdateAsync(update => update.SetProperty(x => x.RegisteredAgentId, agent.Id), cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new("Completed", new(agent.Id, agentToken, now));
    }

    public async Task<IReadOnlyList<DeploymentAgentExchangeDto>> ListExchangesAsync(CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        await db.DeploymentAgentRegistrationExchanges
            .Where(x => x.Status == DeploymentAgentExchangeStatus.Pending && x.ExpiresAtUtc <= now)
            .ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, DeploymentAgentExchangeStatus.Expired), cancellationToken);
        var exchanges = await db.DeploymentAgentRegistrationExchanges.AsNoTracking()
            .OrderByDescending(x => x.CreatedAtUtc).Take(100).ToListAsync(cancellationToken);
        return exchanges.Select(x => new DeploymentAgentExchangeDto(
            x.Id, x.UserCode, x.Name, x.MachineName, x.Version, x.OperatingSystem,
            JsonSerializer.Deserialize<List<string>>(x.CapabilitiesJson) ?? [],
            x.PublicKeyFingerprint, x.Status, x.CreatedAtUtc, x.ExpiresAtUtc, x.ApprovedAtUtc, x.ApprovedBy)).ToList();
    }

    public async Task ApproveExchangeAsync(Guid id, string actor, CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var changed = await db.DeploymentAgentRegistrationExchanges
            .Where(x => x.Id == id && x.Status == DeploymentAgentExchangeStatus.Pending && x.ExpiresAtUtc > now)
            .ExecuteUpdateAsync(update => update
                .SetProperty(x => x.Status, DeploymentAgentExchangeStatus.Approved)
                .SetProperty(x => x.ApprovedAtUtc, now)
                .SetProperty(x => x.ApprovedBy, actor), cancellationToken);
        if (changed != 1) throw new InvalidOperationException("Registration exchange is not pending or has expired.");
    }

    public async Task RejectExchangeAsync(Guid id, string actor, CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var changed = await db.DeploymentAgentRegistrationExchanges
            .Where(x => x.Id == id && x.Status == DeploymentAgentExchangeStatus.Pending)
            .ExecuteUpdateAsync(update => update
                .SetProperty(x => x.Status, DeploymentAgentExchangeStatus.Rejected)
                .SetProperty(x => x.RejectedAtUtc, now)
                .SetProperty(x => x.RejectedBy, actor), cancellationToken);
        if (changed != 1) throw new InvalidOperationException("Registration exchange is not pending.");
    }

    public async Task HeartbeatAsync(
        Guid agentId,
        string? agentToken,
        DeploymentAgentHeartbeatRequest request,
        CancellationToken cancellationToken)
    {
        var agent = await AuthenticateAsync(agentId, agentToken, cancellationToken);
        if (agent.Status is DeploymentAgentStatus.Disabled or DeploymentAgentStatus.Revoked)
            throw new UnauthorizedAccessException("Deployment agent is disabled or revoked.");
        agent.Version = Required(request.Version, "Agent version");
        agent.OperatingSystem = Required(request.OperatingSystem, "Operating system");
        agent.CapabilitiesJson = JsonSerializer.Serialize(NormalizeCapabilities(request.Capabilities));
        agent.Status = request.Busy ? DeploymentAgentStatus.Busy : DeploymentAgentStatus.Online;
        agent.LastHeartbeatAtUtc = DateTime.UtcNow;
        agent.UpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<DeploymentAgentDto>> ListAsync(CancellationToken cancellationToken)
    {
        var agents = await db.DeploymentAgents.AsNoTracking().OrderBy(x => x.Name).ToListAsync(cancellationToken);
        return agents.Select(ToDto).ToList();
    }

    public async Task RevokeAsync(Guid id, CancellationToken cancellationToken)
    {
        var agent = await db.DeploymentAgents.FindAsync([id], cancellationToken)
            ?? throw new KeyNotFoundException("Deployment agent was not found.");
        agent.Status = DeploymentAgentStatus.Revoked;
        agent.RevokedAtUtc = DateTime.UtcNow;
        agent.UpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
    }

    internal async Task<DeploymentAgent> AuthenticateAsync(
        Guid agentId,
        string? agentToken,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(agentToken))
            throw new UnauthorizedAccessException("Deployment agent token is required.");
        var agent = await db.DeploymentAgents.FirstOrDefaultAsync(x => x.Id == agentId, cancellationToken)
            ?? throw new UnauthorizedAccessException("Deployment agent identity is invalid.");
        var supplied = Convert.FromHexString(Hash(agentToken));
        var expected = Convert.FromHexString(agent.AuthenticationTokenHash);
        if (!CryptographicOperations.FixedTimeEquals(supplied, expected))
            throw new UnauthorizedAccessException("Deployment agent token is invalid.");
        return agent;
    }

    private static void ValidateRegistration(DeploymentAgentRegisterRequest request)
    {
        _ = Required(request.RegistrationToken, "Registration token");
        _ = Required(request.Name, "Agent name");
        _ = Required(request.MachineName, "Machine name");
        _ = Required(request.Version, "Agent version");
        _ = Required(request.OperatingSystem, "Operating system");
        if (request.PublicKeyPem is { Length: > 16384 })
            throw new ArgumentException("Agent public key is too large.");
    }

    private static void ValidateExchange(DeploymentAgentExchangeCreateRequest request)
    {
        _ = Required(request.Name, "Agent name");
        _ = Required(request.MachineName, "Machine name");
        _ = Required(request.Version, "Agent version");
        _ = Required(request.OperatingSystem, "Operating system");
        if (string.IsNullOrWhiteSpace(request.PublicKeyPem) || request.PublicKeyPem.Length > 16384)
            throw new ArgumentException("A valid agent public key is required.");
        _ = PublicKeyFingerprint(request.PublicKeyPem);
    }

    private async Task<string> CreateUniqueUserCodeAsync(CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 10; attempt++)
        {
            var bytes = RandomNumberGenerator.GetBytes(8);
            var value = new string(bytes.Select(x => UserCodeAlphabet[x % UserCodeAlphabet.Length]).ToArray());
            var code = $"{value[..4]}-{value[4..]}";
            if (!await db.DeploymentAgentRegistrationExchanges.AnyAsync(x => x.UserCode == code, cancellationToken))
                return code;
        }
        throw new InvalidOperationException("A unique registration approval code could not be generated.");
    }

    private static string PublicKeyFingerprint(string publicKeyPem)
    {
        using var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(publicKeyPem);
        }
        catch (CryptographicException exception)
        {
            throw new ArgumentException("Agent public key is invalid.", exception);
        }
        return Convert.ToHexString(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo()));
    }

    private static string? ExchangeMessage(DeploymentAgentExchangeStatus status) => status switch
    {
        DeploymentAgentExchangeStatus.Pending => "Waiting for administrator approval.",
        DeploymentAgentExchangeStatus.Rejected => "Registration was rejected by an administrator.",
        DeploymentAgentExchangeStatus.Expired => "Registration approval expired.",
        DeploymentAgentExchangeStatus.Completed => "Registration exchange has already been consumed.",
        _ => null
    };

    private static bool FixedHashEquals(string left, string right) =>
        CryptographicOperations.FixedTimeEquals(Convert.FromHexString(left), Convert.FromHexString(right));

    private static DeploymentAgentDto ToDto(DeploymentAgent agent) => new(
        agent.Id,
        agent.Name,
        agent.MachineName,
        agent.Version,
        agent.OperatingSystem,
        JsonSerializer.Deserialize<List<string>>(agent.CapabilitiesJson) ?? [],
        agent.Status,
        agent.LastHeartbeatAtUtc,
        agent.RegisteredAtUtc);

    private static IReadOnlyList<string> NormalizeCapabilities(IReadOnlyList<string>? capabilities) =>
        (capabilities ?? []).Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x).Take(32).ToList();
    private static string Required(string? value, string name) =>
        !string.IsNullOrWhiteSpace(value) ? value.Trim() : throw new ArgumentException($"{name} is required.");
    private static string? Normalize(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    private static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
