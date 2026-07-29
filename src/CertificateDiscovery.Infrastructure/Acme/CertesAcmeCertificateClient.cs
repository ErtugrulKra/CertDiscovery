using System.Reflection;
using Certes;
using Certes.Acme;
using CertificateDiscovery.Application.Acme;
using CertificateDiscovery.Domain.Entities;

namespace CertificateDiscovery.Infrastructure.Acme;

public sealed class CertesAcmeCertificateClient : IAcmeCertificateClient
{
    public async Task TestDirectoryAsync(AcmeProvider provider, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var acme = new AcmeContext(provider.DirectoryUrl);
        _ = await acme.GetDirectory();
    }

    public async Task TestAccountAsync(AcmeProvider provider, AcmeAccountCredentials account, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var acme = new AcmeContext(provider.DirectoryUrl, KeyFactory.FromPem(account.AccountKeyPem));
        var existing = await acme.NewAccount([ToAcmeContact(provider.AccountEmail)], true);
        if (!string.Equals(existing.Location.ToString(), account.AccountLocation, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The ACME server returned a different account location for the stored key.");
        }
    }

    public async Task<string> RotateAccountKeyAsync(AcmeProvider provider, AcmeAccountCredentials account, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var acme = new AcmeContext(provider.DirectoryUrl, KeyFactory.FromPem(account.AccountKeyPem));
        _ = await acme.NewAccount([ToAcmeContact(provider.AccountEmail)], true);
        var newKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
        _ = await acme.ChangeKey(newKey);
        return newKey.ToPem();
    }

    public async Task<AcmeAccountRegistration> RegisterAccountAsync(
        AcmeProvider provider,
        string? eabKeyId,
        string? eabHmacKey,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(eabKeyId) != string.IsNullOrWhiteSpace(eabHmacKey))
        {
            throw new InvalidOperationException("EAB Key ID and HMAC key must be supplied together.");
        }

        var accountKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
        var acme = new AcmeContext(provider.DirectoryUrl, accountKey);
        try
        {
            var account = string.IsNullOrWhiteSpace(eabKeyId)
                ? await acme.NewAccount(ToAcmeContact(provider.AccountEmail), true)
                : await acme.NewAccount(
                    ToAcmeContact(provider.AccountEmail),
                    true,
                    eabKeyId.Trim(),
                    EabKeyNormalizer.Normalize(eabHmacKey!),
                    "HS256");
            return new AcmeAccountRegistration(
                account.Location.ToString(),
                accountKey.ToPem());
        }
        catch (Exception ex) when (IsEabFailure(ex))
        {
            throw new InvalidOperationException("ACME external account binding registration failed. Verify the EAB Key ID, HMAC key and directory URL.", ex);
        }
    }

    public async Task<AcmeOrderContext> CreateOrderAsync(
        AcmeProvider provider,
        AcmeAccountCredentials account,
        IReadOnlyList<string> domains,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var accountKey = KeyFactory.FromPem(account.AccountKeyPem);
        var acme = new AcmeContext(provider.DirectoryUrl, accountKey);
        var existing = await acme.NewAccount([ToAcmeContact(provider.AccountEmail)], true);
        if (!string.Equals(existing.Location.ToString(), account.AccountLocation, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The stored ACME account key resolved to a different account location.");
        }
        var order = await acme.NewOrder(domains.ToList());
        var authorizations = (await order.Authorizations()).ToList();
        var challenges = new List<AcmeChallengeResult>();
        foreach (var authorization in authorizations)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var resource = await GetResourceAsync(authorization);
            var identifier = NormalizeDomain(GetIdentifierValue(resource));
            var challenge = await authorization.Dns();
            challenges.Add(new AcmeChallengeResult(
                identifier,
                ToDnsTxtName(identifier),
                acme.AccountKey.DnsTxt(challenge.Token)));
        }

        return new AcmeOrderContext(
            account.AccountKeyPem,
            GetLocation(order)?.ToString() ?? throw new InvalidOperationException("ACME order location was not returned."),
            challenges);
    }

    public async Task<IssuedCertificateBundle> ValidateAndFinalizeAsync(
        AcmeProvider provider,
        AcmeAccountCredentials account,
        AcmeOrderContext orderContext,
        string commonName,
        CancellationToken cancellationToken)
    {
        var accountKey = KeyFactory.FromPem(account.AccountKeyPem);
        var acme = new AcmeContext(provider.DirectoryUrl, accountKey);
        var order = acme.Order(new Uri(orderContext.OrderLocation));
        var authorizations = (await order.Authorizations()).ToList();
        foreach (var authorization in authorizations)
        {
            var resource = await GetResourceAsync(authorization);
            if (GetStatus(resource) == "Valid") continue;
            var challenge = await authorization.Dns();
            await challenge.Validate();
        }

        await WaitUntilOrderReadyAsync(order, TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(15), cancellationToken);
        var certificateKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
        var chain = await order.Generate(new CsrInfo
        {
            CommonName = commonName,
            Organization = "Certificate Discovery Platform"
        }, certificateKey, retryCount: 10);
        var certificatePem = chain.Certificate.ToPem();
        var issuerPem = string.Join('\n', chain.Issuers.Select(x => x.ToPem()));
        return new IssuedCertificateBundle(certificatePem, certificatePem + issuerPem, certificateKey.ToPem());
    }

    public Task RevokeAsync(
        AcmeProvider provider,
        string accountKeyPem,
        string certificatePem,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException("Certificate revocation is not exposed by the current UI.");

    private static async Task WaitUntilOrderReadyAsync(IOrderContext order, TimeSpan maxWait, TimeSpan interval, CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow.Add(maxWait);
        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var orderResource = await GetResourceAsync(order);
            var orderStatus = GetStatus(orderResource);
            if (orderStatus is "Ready" or "Valid") return;
            if (orderStatus == "Invalid")
            {
                throw new InvalidOperationException("ACME order became invalid during DNS validation.");
            }

            var authorizations = (await order.Authorizations()).ToList();
            var authorizationResources = new List<object>();
            foreach (var authorization in authorizations)
            {
                authorizationResources.Add(await GetResourceAsync(authorization));
            }

            if (authorizationResources.Any(x => GetStatus(x) is "Invalid" or "Expired" or "Deactivated" or "Revoked"))
            {
                var failed = authorizationResources.First(x => GetStatus(x) is "Invalid" or "Expired" or "Deactivated" or "Revoked");
                throw new InvalidOperationException($"ACME authorization failed for {GetIdentifierValue(failed)} with status {GetStatus(failed)}.");
            }

            await Task.Delay(interval, cancellationToken);
        }

        throw new TimeoutException("Timed out while waiting for ACME DNS validation. The request can be retried.");
    }

    private static async Task<object> GetResourceAsync(object context)
    {
        var method = context.GetType().GetMethod("Resource", BindingFlags.Public | BindingFlags.Instance, null, Type.EmptyTypes, null)
            ?? throw new InvalidOperationException($"ACME context {context.GetType().Name} does not expose Resource().");
        var task = method.Invoke(context, null) as Task
            ?? throw new InvalidOperationException("ACME Resource() did not return a task.");
        await task;
        return task.GetType().GetProperty("Result")?.GetValue(task)
            ?? throw new InvalidOperationException("ACME Resource() returned no result.");
    }

    private static string? GetStatus(object resource) =>
        resource.GetType().GetProperty("Status")?.GetValue(resource)?.ToString();

    private static string GetIdentifierValue(object resource)
    {
        var identifier = resource.GetType().GetProperty("Identifier")?.GetValue(resource);
        return identifier?.GetType().GetProperty("Value")?.GetValue(identifier)?.ToString()
            ?? throw new InvalidOperationException("ACME authorization identifier was not returned.");
    }

    private static Uri? GetLocation(object context) =>
        context.GetType().GetProperty("Location")?.GetValue(context) as Uri;

    private static string NormalizeDomain(string value) => value.Trim().TrimEnd('.').ToLowerInvariant();
    private static string ToDnsTxtName(string domain) => $"_acme-challenge.{domain.TrimStart('*').TrimStart('.')}";
    private static string ToAcmeContact(string email) => email.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase) ? email.Trim() : $"mailto:{email.Trim()}";

    private static bool IsEabFailure(Exception ex)
    {
        var message = ex.Message;
        return message.Contains("external", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("eab", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("unauthorized", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("malformed", StringComparison.OrdinalIgnoreCase);
    }
}
