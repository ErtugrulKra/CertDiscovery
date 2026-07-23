namespace CertificateDiscovery.Infrastructure.Services;

using CertificateDiscovery.Contracts;
using CertificateDiscovery.Domain.Entities;
using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

public sealed class WorkerService(CertificateDiscoveryDbContext db)
{
    public async Task HeartbeatAsync(WorkerHeartbeatRequest request, CancellationToken cancellationToken)
    {
        var worker = await db.WorkerNodes.FirstOrDefaultAsync(x => x.WorkerName == request.WorkerName, cancellationToken);
        if (worker is null)
        {
            worker = new Domain.Entities.WorkerNode { WorkerName = request.WorkerName, StartedAtUtc = DateTime.UtcNow };
            db.WorkerNodes.Add(worker);
        }

        worker.Version = request.Version;
        worker.LastHeartbeatAtUtc = DateTime.UtcNow;
        worker.Status = "Online";
        worker.LastError = request.LastError;
        worker.ProcessedJobCount = request.ProcessedJobCount;
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<bool> IsEnabledForClaimsAsync(string workerName, CancellationToken cancellationToken)
    {
        var worker = await db.WorkerNodes.AsNoTracking().FirstOrDefaultAsync(x => x.WorkerName == workerName, cancellationToken);
        return worker is null || worker.IsEnabled;
    }

    public async Task<List<WorkerNodeDto>> ListAsync(CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var workers = await db.WorkerNodes.OrderBy(x => x.WorkerName).ToListAsync(cancellationToken);
        return workers.Select(x => ToDto(x, now)).ToList();
    }

    public async Task<WorkerNodeDto?> GetAsync(Guid id, CancellationToken cancellationToken)
    {
        var worker = await db.WorkerNodes.FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        return worker is null ? null : ToDto(worker, DateTime.UtcNow);
    }

    public async Task<WorkerNode> CreateAsync(string workerName, string? description, bool isEnabled, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(workerName)) throw new ArgumentException("Worker name is required.");
        workerName = workerName.Trim();
        if (await db.WorkerNodes.AnyAsync(x => x.WorkerName == workerName, cancellationToken))
        {
            throw new InvalidOperationException("A worker node with the same name already exists.");
        }

        var worker = new WorkerNode
        {
            WorkerName = workerName,
            Description = Normalize(description),
            IsEnabled = isEnabled,
            Status = isEnabled ? "Offline" : "Disabled",
            LastHeartbeatAtUtc = DateTime.UtcNow,
            StartedAtUtc = DateTime.UtcNow
        };
        db.WorkerNodes.Add(worker);
        await db.SaveChangesAsync(cancellationToken);
        return worker;
    }

    public async Task<bool> UpdateAsync(Guid id, string? description, bool isEnabled, CancellationToken cancellationToken)
    {
        var worker = await db.WorkerNodes.FindAsync([id], cancellationToken);
        if (worker is null) return false;

        worker.Description = Normalize(description);
        worker.IsEnabled = isEnabled;
        worker.UpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task<bool> ToggleAsync(Guid id, CancellationToken cancellationToken)
    {
        var worker = await db.WorkerNodes.FindAsync([id], cancellationToken);
        if (worker is null) return false;

        worker.IsEnabled = !worker.IsEnabled;
        worker.UpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task<bool> DeleteAsync(Guid id, CancellationToken cancellationToken)
    {
        var worker = await db.WorkerNodes.FindAsync([id], cancellationToken);
        if (worker is null) return false;

        db.WorkerNodes.Remove(worker);
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    private static WorkerNodeDto ToDto(WorkerNode worker, DateTime now)
    {
        var age = now - worker.LastHeartbeatAtUtc;
        var status = worker.IsEnabled
            ? age.TotalMinutes <= 2 ? "Online" : age.TotalMinutes <= 10 ? "Stale" : "Offline"
            : "Disabled";
        return new WorkerNodeDto(
            worker.Id,
            worker.WorkerName,
            worker.Description,
            worker.Version,
            status,
            worker.IsEnabled,
            worker.LastHeartbeatAtUtc,
            worker.StartedAtUtc,
            worker.CreatedAtUtc,
            worker.UpdatedAtUtc,
            worker.ProcessedJobCount,
            worker.LastError);
    }

    private static string? Normalize(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
