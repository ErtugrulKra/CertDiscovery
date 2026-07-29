using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace WinDeployAgent;

public sealed class CentralCertificateStore : ICentralCertificateStore
{
    public CcsFileSnapshot Replace(byte[] pfx, string password, IisTargetOptions options)
    {
        var root = Path.GetFullPath(options.CentralCertificateStorePath!);
        if (!Directory.Exists(root))
            throw new DirectoryNotFoundException("The configured Central Certificate Store directory does not exist.");
        var fileName = Path.GetFileName(options.PfxFileName!);
        if (!string.Equals(fileName, options.PfxFileName, StringComparison.Ordinal) ||
            !fileName.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Central Certificate Store pfxFileName must be a safe .pfx file name.");
        var target = Path.GetFullPath(Path.Combine(root, fileName));
        if (!target.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Central Certificate Store target escapes the configured directory.");

        ValidatePfx(pfx, password);
        var temporary = target + $".{Guid.NewGuid():N}.new";
        var backup = File.Exists(target) ? target + $".{DateTime.UtcNow:yyyyMMddHHmmssfff}.bak" : null;
        FileSecurity? permissions = File.Exists(target) ? new FileInfo(target).GetAccessControl() : null;
        try
        {
            using (var stream = new FileStream(
                       temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, FileOptions.WriteThrough))
            {
                stream.Write(pfx);
                stream.Flush(true);
            }
            if (permissions is not null) new FileInfo(temporary).SetAccessControl(permissions);
            if (backup is null)
                File.Move(temporary, target);
            else
                File.Replace(temporary, target, backup, ignoreMetadataErrors: false);
            return new(target, backup, backup is not null);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    public string VerifyFingerprint(CcsFileSnapshot snapshot, string password)
    {
        var bytes = File.ReadAllBytes(snapshot.TargetPath);
        try
        {
            using var certificate = new X509Certificate2(
                bytes, password, X509KeyStorageFlags.MachineKeySet);
            return Convert.ToHexString(SHA256.HashData(certificate.RawData));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public void Restore(CcsFileSnapshot snapshot)
    {
        if (snapshot.Existed && snapshot.BackupPath is not null && File.Exists(snapshot.BackupPath))
        {
            File.Replace(snapshot.BackupPath, snapshot.TargetPath, null, ignoreMetadataErrors: false);
            return;
        }
        if (!snapshot.Existed && File.Exists(snapshot.TargetPath))
            File.Delete(snapshot.TargetPath);
    }

    private static void ValidatePfx(byte[] pfx, string password)
    {
        using var certificate = new X509Certificate2(
            pfx, password, X509KeyStorageFlags.MachineKeySet);
        if (!certificate.HasPrivateKey)
            throw new InvalidOperationException("Central Certificate Store PFX does not contain a private key.");
    }
}
