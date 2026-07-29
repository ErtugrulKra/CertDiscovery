using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using WinDeployAgent.Contracts;

namespace WinDeployAgent;

public sealed class MachineCredentialStore(IOptions<AgentOptions> options)
{
    private readonly string identityPath = Path.Combine(Path.GetFullPath(options.Value.StateDirectory), "identity.dat");
    private readonly string pendingRegistrationPath = Path.Combine(Path.GetFullPath(options.Value.StateDirectory), "registration.dat");
    private readonly string activeJobPath = Path.Combine(Path.GetFullPath(options.Value.StateDirectory), "active-job.dat");

    public async Task<AgentIdentity?> LoadAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(identityPath)) return null;
        var protectedBytes = await File.ReadAllBytesAsync(identityPath, cancellationToken);
        var clearBytes = Unprotect(protectedBytes);
        try
        {
            return JsonSerializer.Deserialize<AgentIdentity>(clearBytes)
                ?? throw new InvalidOperationException("Agent identity is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clearBytes);
        }
    }

    public async Task SaveAsync(AgentIdentity identity, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(identityPath)!);
        var clearBytes = JsonSerializer.SerializeToUtf8Bytes(identity);
        try
        {
            var protectedBytes = Protect(clearBytes);
            await File.WriteAllBytesAsync(identityPath, protectedBytes, cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clearBytes);
        }
    }

    public Task<PendingAgentRegistration?> LoadPendingRegistrationAsync(CancellationToken cancellationToken) =>
        LoadProtectedAsync<PendingAgentRegistration>(pendingRegistrationPath, cancellationToken);

    public Task SavePendingRegistrationAsync(PendingAgentRegistration registration, CancellationToken cancellationToken) =>
        SaveProtectedAsync(pendingRegistrationPath, registration, cancellationToken);

    public void DeletePendingRegistration()
    {
        if (File.Exists(pendingRegistrationPath)) File.Delete(pendingRegistrationPath);
    }

    public Task<AgentJobClaimResponse?> LoadActiveJobAsync(CancellationToken cancellationToken) =>
        LoadProtectedAsync<AgentJobClaimResponse>(activeJobPath, cancellationToken);

    public Task SaveActiveJobAsync(AgentJobClaimResponse job, CancellationToken cancellationToken) =>
        SaveProtectedAsync(activeJobPath, job, cancellationToken);

    public void DeleteActiveJob()
    {
        if (File.Exists(activeJobPath)) File.Delete(activeJobPath);
    }

    private static async Task<T?> LoadProtectedAsync<T>(string path, CancellationToken cancellationToken)
    {
        if (!File.Exists(path)) return default;
        var protectedBytes = await File.ReadAllBytesAsync(path, cancellationToken);
        var clearBytes = Unprotect(protectedBytes);
        try
        {
            return JsonSerializer.Deserialize<T>(clearBytes)
                ?? throw new InvalidOperationException("Protected agent state is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clearBytes);
        }
    }

    private static async Task SaveProtectedAsync<T>(string path, T value, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var clearBytes = JsonSerializer.SerializeToUtf8Bytes(value);
        try
        {
            var protectedBytes = Protect(clearBytes);
            var temporaryPath = path + ".new";
            await File.WriteAllBytesAsync(temporaryPath, protectedBytes, cancellationToken);
            File.Move(temporaryPath, path, true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clearBytes);
        }
    }

    private static byte[] Protect(byte[] value) => Transform(value, protect: true);
    private static byte[] Unprotect(byte[] value) => Transform(value, protect: false);

    private static byte[] Transform(byte[] value, bool protect)
    {
        var input = ToBlob(value);
        DATA_BLOB output = default;
        try
        {
            var succeeded = protect
                ? CryptProtectData(ref input, "CertDiscovery winDeployAgent identity", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0x4, ref output)
                : CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0x4, ref output);
            if (!succeeded) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            var result = new byte[output.cbData];
            Marshal.Copy(output.pbData, result, 0, output.cbData);
            return result;
        }
        finally
        {
            if (input.pbData != IntPtr.Zero) Marshal.FreeHGlobal(input.pbData);
            if (output.pbData != IntPtr.Zero) LocalFree(output.pbData);
        }
    }

    private static DATA_BLOB ToBlob(byte[] value)
    {
        var pointer = Marshal.AllocHGlobal(value.Length);
        Marshal.Copy(value, 0, pointer, value.Length);
        return new(value.Length, pointer);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DATA_BLOB(int size, IntPtr data)
    {
        public int cbData = size;
        public IntPtr pbData = data;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptProtectData(
        ref DATA_BLOB dataIn, string description, IntPtr optionalEntropy, IntPtr reserved,
        IntPtr promptStruct, int flags, ref DATA_BLOB dataOut);
    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptUnprotectData(
        ref DATA_BLOB dataIn, IntPtr description, IntPtr optionalEntropy, IntPtr reserved,
        IntPtr promptStruct, int flags, ref DATA_BLOB dataOut);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
