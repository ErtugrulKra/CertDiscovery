using CertificateDiscovery.Application.Secrets;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;

namespace CertificateDiscovery.Infrastructure.Secrets;

public sealed class ProtectedDbSecretProvider(
    CertificateDiscoveryDbContext db,
    IDataProtectionProvider dataProtectionProvider) : ISecretProvider
{
    private const string Prefix = "db-protected:";
    private readonly IDataProtector protector = dataProtectionProvider.CreateProtector("CertificateDiscovery.Secrets.v1");

    public async Task<string> StoreAsync(string purpose, string value, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(value)) throw new ArgumentException("Secret value cannot be empty.", nameof(value));
        var record = new SecretRecord
        {
            Purpose = purpose.Trim(),
            ProtectedValue = protector.Protect(value)
        };
        db.SecretRecords.Add(record);
        await db.SaveChangesAsync(cancellationToken);
        return Prefix + record.Id.ToString("D");
    }

    public async Task<string> GetAsync(string secretReference, CancellationToken cancellationToken)
    {
        var id = ParseReference(secretReference);
        var record = await db.SecretRecords.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, cancellationToken)
            ?? throw new InvalidOperationException("The referenced secret was not found.");
        return protector.Unprotect(record.ProtectedValue);
    }

    public async Task DeleteAsync(string secretReference, CancellationToken cancellationToken)
    {
        var id = ParseReference(secretReference);
        var record = await db.SecretRecords.FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (record is null) return;
        db.SecretRecords.Remove(record);
        await db.SaveChangesAsync(cancellationToken);
    }

    private static Guid ParseReference(string secretReference)
    {
        if (!secretReference.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase) ||
            !Guid.TryParse(secretReference[Prefix.Length..], out var id))
        {
            throw new InvalidOperationException("The secret reference format is invalid.");
        }

        return id;
    }
}

