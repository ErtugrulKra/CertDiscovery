namespace CertificateDiscovery.Infrastructure.Persistence;

using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;

public static class AuthenticationSeeder
{
    public static async Task SeedInitialAdminAsync(CertificateDiscoveryDbContext db, CancellationToken cancellationToken)
    {
        if (await db.AppUsers.AnyAsync(cancellationToken)) return;

        db.AppUsers.Add(new AppUser
        {
            UserName = "Admin",
            DisplayName = "System Administrator",
            PasswordHash = PasswordHasher.Hash("Admin123"),
            Role = "Admin",
            IsEnabled = true,
            CreatedAtUtc = DateTime.UtcNow
        });
        await db.SaveChangesAsync(cancellationToken);
    }
}
