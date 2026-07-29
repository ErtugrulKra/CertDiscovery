# Current Certificate Lifecycle Data Model

`AcmeProvider` stores provider type, directory URL, account email, optional EAB
credentials, staging flag and enabled state.

`DnsProvider` stores provider type, zone name, API token, notes and enabled state.
Only Cloudflare is implemented for automatic publication.

`VaultServer` stores URL, token, discovery settings and last synchronization
result.

`AcmeCertificateRequest` is both workflow state and working secret storage. It
links to one ACME provider and Vault server, and optionally a DNS provider and
inventory certificate. It stores normalized names, status, DNS instructions,
ACME account key and order URL, certificate private key and PEM bundle, publish
results, schedule state and renewal links.

`Certificate` is deduplicated by SHA-256 fingerprint. It stores parsed X.509
metadata, source, Vault path and leaf PEM. Related
`CertificateSubjectAlternativeName` and `CertificateChainEntry` rows contain the
name set and parsed chain.

Current request transitions observed in production code:

```text
Draft -> PendingDns
Failed -> PendingDns
PendingDns | ReadyToValidate | Failed -> Validating
Validating -> Issued -> StoredInVault
Validating -> ReadyToValidate (timeout)
Validating -> Failed (other error)
StoredInVault -> Draft (scheduled renewal reset)
```

Transitions are assigned directly and are not currently enforced by a central
state machine.

