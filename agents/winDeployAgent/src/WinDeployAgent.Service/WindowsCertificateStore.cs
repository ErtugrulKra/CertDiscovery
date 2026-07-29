using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace WinDeployAgent;

public sealed class WindowsCertificateStore : IWindowsCertificateStore
{
    public CertificateImportResult Import(byte[] pfx, string password, string storeName)
    {
        var collection = new X509Certificate2Collection();
        collection.Import(
            pfx,
            password,
            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
        var leaf = collection.Cast<X509Certificate2>().FirstOrDefault(x => x.HasPrivateKey)
            ?? throw new InvalidOperationException("The received PFX does not contain a certificate with a private key.");

        using var store = Open(storeName, OpenFlags.ReadWrite);
        var added = new List<byte[]>();
        foreach (var certificate in collection.Cast<X509Certificate2>())
        {
            if (store.Certificates.Find(X509FindType.FindByThumbprint, certificate.Thumbprint, false).Count != 0)
                continue;
            store.Add(certificate);
            added.Add(certificate.GetCertHash());
        }

        return new(
            leaf.GetCertHash(),
            Convert.ToHexString(SHA256.HashData(leaf.RawData)),
            added);
    }

    public string? FindSha256Fingerprint(byte[]? bindingHash, string? storeName)
    {
        if (bindingHash is null || bindingHash.Length == 0 || string.IsNullOrWhiteSpace(storeName))
            return null;
        using var store = Open(storeName, OpenFlags.ReadOnly);
        var certificate = store.Certificates
            .Cast<X509Certificate2>()
            .FirstOrDefault(x => CryptographicOperations.FixedTimeEquals(x.GetCertHash(), bindingHash));
        return certificate is null ? null : Convert.ToHexString(SHA256.HashData(certificate.RawData));
    }

    public void Remove(IReadOnlyList<byte[]> certificateHashes, string storeName)
    {
        if (certificateHashes.Count == 0) return;
        using var store = Open(storeName, OpenFlags.ReadWrite);
        foreach (var hash in certificateHashes)
        {
            var certificate = store.Certificates.Cast<X509Certificate2>()
                .FirstOrDefault(x => CryptographicOperations.FixedTimeEquals(x.GetCertHash(), hash));
            if (certificate is not null) store.Remove(certificate);
        }
    }

    private static X509Store Open(string name, OpenFlags flags)
    {
        var store = new X509Store(name, StoreLocation.LocalMachine);
        store.Open(flags);
        return store;
    }
}
