namespace CertificateDiscovery.Infrastructure.Services;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Mapping;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

public sealed class AssetService(CertificateDiscoveryDbContext db)
{
    public async Task<List<AssetDto>> ListAsync(AssetFilter filter, CancellationToken cancellationToken)
    {
        var query = db.Assets
            .Include(x => x.AssetCertificates).ThenInclude(x => x.Certificate)
            .Include(x => x.ScanResults)
            .AsQueryable();

        if (filter.Environment is not null) query = query.Where(x => x.Environment == filter.Environment);
        if (filter.Protocol is not null) query = query.Where(x => x.Protocol == filter.Protocol);
        if (filter.AssetType is not null) query = query.Where(x => x.AssetType == filter.AssetType);
        if (!string.IsNullOrWhiteSpace(filter.Owner)) query = query.Where(x => x.Owner == filter.Owner);
        if (filter.IsEnabled is not null) query = query.Where(x => x.IsEnabled == filter.IsEnabled);
        if (filter.ExpiresWithinDays is not null)
        {
            var until = DateTime.UtcNow.AddDays(filter.ExpiresWithinDays.Value);
            query = query.Where(x => x.AssetCertificates.Any(ac => ac.IsCurrentlyActive && ac.Certificate.NotAfterUtc <= until));
        }

        var assets = await query.OrderBy(x => x.Name).ToListAsync(cancellationToken);
        return assets.Select(DtoMapper.ToDto).ToList();
    }

    public async Task<AssetDto?> GetAsync(Guid id, CancellationToken cancellationToken)
    {
        var asset = await db.Assets
            .Include(x => x.AssetCertificates.OrderByDescending(ac => ac.LastSeenAtUtc)).ThenInclude(x => x.Certificate).ThenInclude(x => x.SubjectAlternativeNames)
            .Include(x => x.ScanResults.OrderByDescending(sr => sr.CompletedAtUtc))
            .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        return asset is null ? null : DtoMapper.ToDto(asset);
    }

    public async Task<Asset> CreateAsync(AssetCreateRequest request, CancellationToken cancellationToken)
    {
        Validate(request.Name, request.Host, request.Port, request.ScanIntervalMinutes, request.TimeoutSeconds);
        var asset = new Asset
        {
            Name = request.Name.Trim(),
            Host = request.Host.Trim(),
            Port = request.Port,
            Protocol = request.Protocol,
            Description = request.Description,
            Path = request.Path,
            SniHost = request.SniHost,
            Environment = request.Environment,
            AssetType = request.AssetType,
            Owner = request.Owner,
            IsEnabled = request.IsEnabled,
            ScanIntervalMinutes = request.ScanIntervalMinutes,
            TimeoutSeconds = request.TimeoutSeconds,
            Tags = request.Tags,
            NextScanAtUtc = DateTime.UtcNow
        };
        db.Assets.Add(asset);
        await db.SaveChangesAsync(cancellationToken);
        return asset;
    }

    public async Task<bool> UpdateAsync(Guid id, AssetUpdateRequest request, CancellationToken cancellationToken)
    {
        Validate(request.Name, request.Host, request.Port, request.ScanIntervalMinutes, request.TimeoutSeconds);
        var asset = await db.Assets.FindAsync([id], cancellationToken);
        if (asset is null) return false;

        asset.Name = request.Name.Trim();
        asset.Host = request.Host.Trim();
        asset.Port = request.Port;
        asset.Protocol = request.Protocol;
        asset.Description = request.Description;
        asset.Path = request.Path;
        asset.SniHost = request.SniHost;
        asset.Environment = request.Environment;
        asset.AssetType = request.AssetType;
        asset.Owner = request.Owner;
        asset.IsEnabled = request.IsEnabled;
        asset.ScanIntervalMinutes = request.ScanIntervalMinutes;
        asset.TimeoutSeconds = request.TimeoutSeconds;
        asset.Tags = request.Tags;
        asset.UpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task<bool> DeleteAsync(Guid id, CancellationToken cancellationToken)
    {
        var asset = await db.Assets.FindAsync([id], cancellationToken);
        if (asset is null) return false;
        db.Assets.Remove(asset);
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    private static void Validate(string name, string host, int port, int interval, int timeout)
    {
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("Asset name is required.");
        if (string.IsNullOrWhiteSpace(host)) throw new ArgumentException("Host is required.");
        if (port is < 1 or > 65535) throw new ArgumentException("Port must be between 1 and 65535.");
        if (interval < 1) throw new ArgumentException("Scan interval must be at least 1 minute.");
        if (timeout is < 1 or > 120) throw new ArgumentException("Timeout must be between 1 and 120 seconds.");
    }
}
