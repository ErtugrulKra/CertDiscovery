namespace CertificateDiscovery.UnitTests;

using CertificateDiscovery.Infrastructure.Persistence;
using CertificateDiscovery.Infrastructure.Security;
using CertificateDiscovery.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;

public sealed class UserServiceTests
{
    [Fact]
    public async Task SeedInitialAdminAsync_CreatesDefaultAdminWhenNoUsersExist()
    {
        await using var db = CreateDb();

        await AuthenticationSeeder.SeedInitialAdminAsync(db, CancellationToken.None);

        var user = await db.AppUsers.SingleAsync();
        Assert.Equal("Admin", user.UserName);
        Assert.Equal("Admin", user.Role);
        Assert.True(PasswordHasher.Verify("Admin123", user.PasswordHash));
    }

    [Fact]
    public async Task ValidateCredentialsAsync_ReturnsUserForCorrectPassword()
    {
        await using var db = CreateDb();
        await AuthenticationSeeder.SeedInitialAdminAsync(db, CancellationToken.None);
        var service = new UserService(db);

        var user = await service.ValidateCredentialsAsync("Admin", "Admin123", CancellationToken.None);

        Assert.NotNull(user);
        Assert.NotNull(user!.LastLoginAtUtc);
    }

    [Fact]
    public async Task ChangePasswordAsync_UpdatesPasswordWhenCurrentPasswordMatches()
    {
        await using var db = CreateDb();
        await AuthenticationSeeder.SeedInitialAdminAsync(db, CancellationToken.None);
        var service = new UserService(db);
        var user = await db.AppUsers.SingleAsync();

        await service.ChangePasswordAsync(user.Id, "Admin123", "NewAdmin123", "NewAdmin123", CancellationToken.None);

        var updated = await db.AppUsers.SingleAsync();
        Assert.False(PasswordHasher.Verify("Admin123", updated.PasswordHash));
        Assert.True(PasswordHasher.Verify("NewAdmin123", updated.PasswordHash));
    }

    [Fact]
    public async Task ChangePasswordAsync_RejectsWrongCurrentPassword()
    {
        await using var db = CreateDb();
        await AuthenticationSeeder.SeedInitialAdminAsync(db, CancellationToken.None);
        var service = new UserService(db);
        var user = await db.AppUsers.SingleAsync();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.ChangePasswordAsync(user.Id, "wrong-password", "NewAdmin123", "NewAdmin123", CancellationToken.None));
    }

    private static CertificateDiscoveryDbContext CreateDb()
    {
        var options = new DbContextOptionsBuilder<CertificateDiscoveryDbContext>()
            .UseSqlite("Data Source=:memory:")
            .Options;
        var db = new CertificateDiscoveryDbContext(options);
        db.Database.OpenConnection();
        db.Database.EnsureCreated();
        return db;
    }
}
