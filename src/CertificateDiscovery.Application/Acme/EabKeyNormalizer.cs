namespace CertificateDiscovery.Application.Acme;

public static class EabKeyNormalizer
{
    public static string Normalize(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) throw new ArgumentException("EAB HMAC key is required.", nameof(value));
        var compact = value.Trim().Replace('-', '+').Replace('_', '/');
        compact = compact.PadRight(compact.Length + (4 - compact.Length % 4) % 4, '=');
        try
        {
            var bytes = Convert.FromBase64String(compact);
            return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("EAB HMAC key must be valid base64 or base64url.", nameof(value), ex);
        }
    }
}

