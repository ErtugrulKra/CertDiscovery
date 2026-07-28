using System.Collections.Concurrent;
using CertificateDiscovery.Application.Acme;
using CertificateDiscovery.Application.Secrets;
using CertificateDiscovery.Domain;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CertificateDiscovery.Infrastructure.Acme;

public sealed class AcmeAccountService(
    CertificateDiscoveryDbContext db,
    IAcmeCertificateClient acmeClient,
    ISecretProvider secretProvider) : IAcmeAccountService
{
    private static readonly ConcurrentDictionary<Guid, SemaphoreSlim> ProviderLocks = new();

    public async Task<AcmeAccountCredentials> GetOrCreateAsync(AcmeProvider provider, CancellationToken cancellationToken)
    {
        if (!provider.IsEnabled) throw new InvalidOperationException($"ACME provider '{provider.Name}' is disabled.");
        var gate = ProviderLocks.GetOrAdd(provider.Id, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken);
        try
        {
            var existing = await db.AcmeAccounts
                .FirstOrDefaultAsync(x => x.AcmeProviderId == provider.Id && x.Status == AcmeAccountStatus.Active, cancellationToken);
            if (existing is not null)
            {
                AddEvent(existing.AcmeProviderId, existing.Id, "AccountReused", "Existing active ACME account was selected.");
                return await ToCredentialsAsync(existing, cancellationToken);
            }

            var hmac = await GetEabHmacAsync(provider, cancellationToken);
            var registration = await RegisterWithRetryAsync(provider, hmac, cancellationToken);
            var keyReference = await secretProvider.StoreAsync(
                $"acme-account-key:{provider.Id:D}",
                registration.AccountKeyPem,
                cancellationToken);
            var account = new AcmeAccount
            {
                AcmeProviderId = provider.Id,
                AccountLocation = registration.AccountLocation,
                AccountKeySecretReference = keyReference,
                ExternalAccountBindingKeyId = provider.ExternalAccountBindingKeyId,
                ContactEmail = provider.AccountEmail,
                Status = AcmeAccountStatus.Active,
                LastUsedAtUtc = DateTime.UtcNow
            };
            db.AcmeAccounts.Add(account);
            AddEvent(provider.Id, account.Id, "AccountRegistered", "ACME account registration completed.");
            await db.SaveChangesAsync(cancellationToken);
            return new AcmeAccountCredentials(account.Id, account.AccountLocation, registration.AccountKeyPem);
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task<AcmeAccountCredentials> GetCredentialsAsync(Guid accountId, CancellationToken cancellationToken)
    {
        var account = await db.AcmeAccounts.FirstOrDefaultAsync(x => x.Id == accountId, cancellationToken)
            ?? throw new InvalidOperationException("ACME account was not found.");
        if (account.Status != AcmeAccountStatus.Active) throw new InvalidOperationException("ACME account is not active.");
        account.LastUsedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
        return await ToCredentialsAsync(account, cancellationToken);
    }

    public async Task DisableAsync(Guid accountId, CancellationToken cancellationToken)
    {
        var account = await db.AcmeAccounts.FirstOrDefaultAsync(x => x.Id == accountId, cancellationToken)
            ?? throw new InvalidOperationException("ACME account was not found.");
        account.Status = AcmeAccountStatus.Disabled;
        account.UpdatedAtUtc = DateTime.UtcNow;
        AddEvent(account.AcmeProviderId, account.Id, "AccountDisabled", "ACME account was disabled.");
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task RotateKeyAsync(Guid accountId, CancellationToken cancellationToken)
    {
        var account = await db.AcmeAccounts.Include(x => x.AcmeProvider).FirstOrDefaultAsync(x => x.Id == accountId, cancellationToken)
            ?? throw new InvalidOperationException("ACME account was not found.");
        if (account.Status != AcmeAccountStatus.Active) throw new InvalidOperationException("ACME account is not active.");
        var credentials = await ToCredentialsAsync(account, cancellationToken);
        var newKey = await acmeClient.RotateAccountKeyAsync(account.AcmeProvider!, credentials, cancellationToken);
        var previousReference = account.AccountKeySecretReference;
        account.AccountKeySecretReference = await secretProvider.StoreAsync(
            $"acme-account-key:{account.AcmeProviderId:D}",
            newKey,
            cancellationToken);
        account.UpdatedAtUtc = DateTime.UtcNow;
        AddEvent(account.AcmeProviderId, account.Id, "AccountKeyRotated", "ACME account key was rotated.");
        await db.SaveChangesAsync(cancellationToken);
        await secretProvider.DeleteAsync(previousReference, cancellationToken);
    }

    private async Task<AcmeAccountCredentials> ToCredentialsAsync(AcmeAccount account, CancellationToken cancellationToken)
    {
        account.LastUsedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
        var key = await secretProvider.GetAsync(account.AccountKeySecretReference, cancellationToken);
        return new AcmeAccountCredentials(account.Id, account.AccountLocation, key);
    }

    private async Task<string?> GetEabHmacAsync(AcmeProvider provider, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(provider.ExternalAccountBindingHmacSecretReference))
        {
            return await secretProvider.GetAsync(provider.ExternalAccountBindingHmacSecretReference, cancellationToken);
        }

        return string.IsNullOrWhiteSpace(provider.ExternalAccountBindingHmacKey)
            ? null
            : provider.ExternalAccountBindingHmacKey;
    }

    private async Task<AcmeAccountRegistration> RegisterWithRetryAsync(
        AcmeProvider provider,
        string? hmac,
        CancellationToken cancellationToken)
    {
        try
        {
            return await acmeClient.RegisterAccountAsync(
                provider,
                provider.ExternalAccountBindingKeyId,
                hmac,
                cancellationToken);
        }
        catch (Exception ex) when (ex is HttpRequestException or TimeoutException)
        {
            await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
            return await acmeClient.RegisterAccountAsync(
                provider,
                provider.ExternalAccountBindingKeyId,
                hmac,
                cancellationToken);
        }
    }

    private void AddEvent(Guid providerId, Guid? accountId, string eventType, string message) =>
        db.AcmeAccountEvents.Add(new AcmeAccountEvent
        {
            AcmeProviderId = providerId,
            AcmeAccountId = accountId,
            EventType = eventType,
            Message = message
        });
}
