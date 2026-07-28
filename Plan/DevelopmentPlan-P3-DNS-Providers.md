# Development Plan P3 — AWS Route53 and Azure DNS

## Objective

Add enterprise DNS-01 automation through AWS Route53 and Microsoft Azure DNS using the provider interfaces introduced in P1.

## Shared Requirements

Every DNS provider must:

- Publish multiple TXT challenges
- Preserve unrelated TXT values
- Wait for propagation
- Clean up only values created by CertDiscovery
- Be idempotent
- Produce actionable errors
- Never log credentials
- Support wildcard and SAN orders
- Have contract tests

---

## Track A — AWS Route53

### P3.A1 — Provider Type and Configuration

Add:

```text
DnsProviderType.Route53
```

Configuration:

```text
Name
ZoneName
HostedZoneId optional
AuthenticationMode
RoleArn optional
AccessKeySecretReference optional
SecretKeySecretReference optional
SessionTokenSecretReference optional
Region optional
Enabled
```

Authentication modes:

1. Default AWS credential chain
2. IAM role
3. EKS IRSA/workload identity
4. Static access key as fallback

### P3.A2 — Hosted Zone Resolver

Rules:

- Normalize wildcard names.
- Match the longest valid hosted zone.
- Support explicit hosted zone ID.
- Distinguish public and private hosted zones.
- Return clear ambiguity errors.

### P3.A3 — TXT Record Publishing

Implementation rules:

- Read existing record set.
- Add the new challenge value without deleting existing values.
- Use UPSERT safely.
- Track values added by the current order.
- Handle multiple authorizations for the same record name.

### P3.A4 — Propagation

Use:

1. Route53 change status polling until `INSYNC`
2. Authoritative DNS TXT lookup
3. Configurable timeout and interval

### P3.A5 — Cleanup

- Remove only the challenge values created by this order.
- Delete record set only when no values remain.
- Cleanup must be retryable.
- Cleanup failure must not hide successful issuance.

---

## Track B — Azure DNS

### P3.B1 — Provider Type and Configuration

Add:

```text
DnsProviderType.AzureDns
```

Configuration:

```text
Name
TenantId optional
SubscriptionId
ResourceGroup
ZoneName
AuthenticationMode
ClientId optional
ClientSecretReference optional
ManagedIdentityClientId optional
Enabled
```

Authentication modes:

1. Managed Identity
2. Workload Identity
3. DefaultAzureCredential
4. Service principal

### P3.B2 — Azure Zone Resolver

- Validate subscription and resource group.
- Verify zone exists.
- Normalize FQDN to relative record set name.
- Support apex and delegated challenge zones.

### P3.B3 — TXT Record Publishing

- Read the existing TXT record set.
- Preserve unrelated TXT values.
- Add one or more ACME challenge values.
- Configure TTL.
- Use ETag/concurrency protection where available.

### P3.B4 — Propagation

- Query authoritative DNS.
- Use configurable polling.
- Return observed and expected values in diagnostics.
- Support multiple SAN challenges.

### P3.B5 — Cleanup

- Remove only CertDiscovery-created values.
- Delete empty record sets.
- Retry transient Azure errors.

---

## Shared Provider Configuration UI

Update `/Integrations`:

- Dynamic form by provider type
- Test credentials
- Test zone access
- Test TXT create/delete with safe temporary record
- Mask all secrets
- Show last health-check result

## Shared Tests

Create a provider contract test suite:

```text
DnsChallengeProviderContractTests
```

Every provider must pass:

- Publish new TXT
- Preserve existing TXT
- Publish duplicate idempotently
- Publish multiple values
- Wait for propagation
- Cleanup owned value
- Preserve unrelated values
- Handle authorization failure
- Handle timeout
- Redact secrets from exceptions and logs

## Acceptance Criteria

- [ ] Route53 provider is available.
- [ ] Azure DNS provider is available.
- [ ] Both support standard and wildcard certificates.
- [ ] Both preserve existing TXT values.
- [ ] Both perform propagation checks.
- [ ] Both clean up safely.
- [ ] Both support cloud-native identity mechanisms.
- [ ] Both pass shared contract tests.
- [ ] Existing Cloudflare behavior still passes the same contract tests.
- [ ] UI can test provider connectivity and zone access.

## VibeCode Prompt

```text
Implement AWS Route53 and Microsoft Azure DNS as IDnsChallengeProvider
implementations.

Use AWS default credentials, IAM roles and optional static credentials for
Route53. Use DefaultAzureCredential, managed identity, workload identity and
optional service principal credentials for Azure DNS.

Both providers must preserve existing TXT values, publish multiple ACME
challenges, verify propagation through authoritative DNS, clean up only values
created by CertDiscovery, and be idempotent.

Create a shared DNS provider contract test suite and make Cloudflare, Route53 and
Azure DNS pass it. Do not add provider-specific logic to
CertificateRequestService.
```
