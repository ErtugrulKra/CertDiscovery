using Microsoft.Web.Administration;

namespace WinDeployAgent;

public sealed class MicrosoftIisBindingStore : IIisBindingStore
{
    public IisBindingSnapshot Capture(IisTargetOptions options)
    {
        using var manager = new ServerManager();
        var site = manager.Sites[options.SiteName]
            ?? throw new InvalidOperationException($"Microsoft IIS site '{options.SiteName}' was not found.");
        var expected = $"{options.BindingIpAddress}:{options.BindingPort}:{options.BindingHost}";
        var binding = site.Bindings.FirstOrDefault(x =>
            string.Equals(x.Protocol, options.BindingProtocol, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(x.BindingInformation, expected, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException($"HTTPS binding '{expected}' was not found on site '{options.SiteName}'.");
        var sniEnabled = (binding.SslFlags & SslFlags.Sni) == SslFlags.Sni;
        if (sniEnabled != options.SniEnabled)
            throw new InvalidOperationException("The configured SNI setting does not match the existing Microsoft IIS binding.");

        return new(
            site.Name,
            binding.BindingInformation,
            binding.Protocol,
            binding.CertificateHash?.ToArray(),
            binding.CertificateStoreName,
            (int)binding.SslFlags,
            options.ApplicationPool);
    }

    public void Apply(IisBindingSnapshot snapshot, byte[] certificateHash, string certificateStoreName, bool recycleApplicationPool)
    {
        using var manager = new ServerManager();
        Replace(manager, snapshot, certificateHash, certificateStoreName);
        manager.CommitChanges();
        if (recycleApplicationPool) Recycle(manager, snapshot.ApplicationPool);
    }

    public void Restore(IisBindingSnapshot snapshot, bool recycleApplicationPool)
    {
        using var manager = new ServerManager();
        Replace(manager, snapshot, snapshot.CertificateHash, snapshot.CertificateStoreName);
        manager.CommitChanges();
        if (recycleApplicationPool) Recycle(manager, snapshot.ApplicationPool);
    }

    public bool IsApplied(IisBindingSnapshot snapshot, byte[] certificateHash, string certificateStoreName)
    {
        using var manager = new ServerManager();
        var binding = Find(manager, snapshot);
        return binding.CertificateHash is not null &&
               binding.CertificateHash.SequenceEqual(certificateHash) &&
               string.Equals(binding.CertificateStoreName, certificateStoreName, StringComparison.OrdinalIgnoreCase) &&
               (int)binding.SslFlags == snapshot.SslFlags &&
               string.Equals(binding.BindingInformation, snapshot.BindingInformation, StringComparison.Ordinal);
    }

    public bool UsesCentralCertificateStore(IisBindingSnapshot snapshot)
    {
        using var manager = new ServerManager();
        var binding = Find(manager, snapshot);
        return (binding.SslFlags & SslFlags.CentralCertStore) == SslFlags.CentralCertStore;
    }

    private static Binding Find(ServerManager manager, IisBindingSnapshot snapshot)
    {
        var site = manager.Sites[snapshot.SiteName]
            ?? throw new InvalidOperationException($"Microsoft IIS site '{snapshot.SiteName}' was not found.");
        return site.Bindings.FirstOrDefault(x =>
                   string.Equals(x.Protocol, snapshot.Protocol, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(x.BindingInformation, snapshot.BindingInformation, StringComparison.OrdinalIgnoreCase))
               ?? throw new InvalidOperationException($"Microsoft IIS binding '{snapshot.BindingInformation}' was not found.");
    }

    private static void Replace(
        ServerManager manager,
        IisBindingSnapshot snapshot,
        byte[]? certificateHash,
        string? certificateStoreName)
    {
        var site = manager.Sites[snapshot.SiteName]
            ?? throw new InvalidOperationException($"Microsoft IIS site '{snapshot.SiteName}' was not found.");
        var current = Find(manager, snapshot);
        site.Bindings.Remove(current);
        if (certificateHash is { Length: > 0 } && !string.IsNullOrWhiteSpace(certificateStoreName))
        {
            site.Bindings.Add(
                snapshot.BindingInformation,
                certificateHash,
                certificateStoreName,
                (SslFlags)snapshot.SslFlags);
        }
        else
        {
            var restored = site.Bindings.Add(snapshot.BindingInformation, snapshot.Protocol);
            restored.SslFlags = (SslFlags)snapshot.SslFlags;
        }
    }

    private static void Recycle(ServerManager manager, string? applicationPool)
    {
        if (string.IsNullOrWhiteSpace(applicationPool)) return;
        var pool = manager.ApplicationPools[applicationPool]
            ?? throw new InvalidOperationException($"Microsoft IIS application pool '{applicationPool}' was not found.");
        pool.Recycle();
    }
}
