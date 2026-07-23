namespace CertificateDiscovery.Infrastructure.Services;

using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using CertificateDiscovery.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;

public sealed class UserService(CertificateDiscoveryDbContext db)
{
    public async Task<List<AppUser>> ListAsync(CancellationToken cancellationToken) =>
        await db.AppUsers.OrderBy(x => x.UserName).ToListAsync(cancellationToken);

    public async Task<AppUser?> GetAsync(Guid id, CancellationToken cancellationToken) =>
        await db.AppUsers.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

    public async Task<AppUser?> ValidateCredentialsAsync(string userName, string password, CancellationToken cancellationToken)
    {
        var user = await db.AppUsers.FirstOrDefaultAsync(x => x.UserName == userName && x.IsEnabled, cancellationToken);
        if (user is null || !PasswordHasher.Verify(password, user.PasswordHash)) return null;

        user.LastLoginAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
        return user;
    }

    public async Task<AppUser> CreateAsync(string userName, string displayName, string role, string password, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(userName)) throw new ArgumentException("User name is required.");
        if (string.IsNullOrWhiteSpace(password) || password.Length < 8) throw new ArgumentException("Password must be at least 8 characters.");
        if (role is not ("Admin" or "Read")) throw new ArgumentException("Role must be Admin or Read.");
        if (await db.AppUsers.AnyAsync(x => x.UserName == userName, cancellationToken)) throw new InvalidOperationException("User name already exists.");

        var user = new AppUser
        {
            UserName = userName.Trim(),
            DisplayName = string.IsNullOrWhiteSpace(displayName) ? userName.Trim() : displayName.Trim(),
            Role = role,
            PasswordHash = PasswordHasher.Hash(password),
            CreatedAtUtc = DateTime.UtcNow,
            IsEnabled = true
        };
        db.AppUsers.Add(user);
        await db.SaveChangesAsync(cancellationToken);
        return user;
    }

    public async Task<bool> ToggleAsync(Guid id, CancellationToken cancellationToken)
    {
        var user = await db.AppUsers.FindAsync([id], cancellationToken);
        if (user is null) return false;
        user.IsEnabled = !user.IsEnabled;
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task<AppUser> UpdateProfileAsync(Guid id, string displayName, CancellationToken cancellationToken)
    {
        var user = await db.AppUsers.FirstOrDefaultAsync(x => x.Id == id && x.IsEnabled, cancellationToken)
            ?? throw new InvalidOperationException("User was not found or is disabled.");
        if (string.IsNullOrWhiteSpace(displayName)) throw new ArgumentException("Display name is required.");

        user.DisplayName = displayName.Trim();
        await db.SaveChangesAsync(cancellationToken);
        return user;
    }

    public async Task ChangePasswordAsync(Guid id, string currentPassword, string newPassword, string confirmPassword, CancellationToken cancellationToken)
    {
        var user = await db.AppUsers.FirstOrDefaultAsync(x => x.Id == id && x.IsEnabled, cancellationToken)
            ?? throw new InvalidOperationException("User was not found or is disabled.");
        if (!PasswordHasher.Verify(currentPassword, user.PasswordHash)) throw new InvalidOperationException("Current password is incorrect.");
        if (string.IsNullOrWhiteSpace(newPassword) || newPassword.Length < 8) throw new ArgumentException("New password must be at least 8 characters.");
        if (newPassword != confirmPassword) throw new ArgumentException("New password and confirmation do not match.");
        if (PasswordHasher.Verify(newPassword, user.PasswordHash)) throw new ArgumentException("New password must be different from the current password.");

        user.PasswordHash = PasswordHasher.Hash(newPassword);
        await db.SaveChangesAsync(cancellationToken);
    }
}
