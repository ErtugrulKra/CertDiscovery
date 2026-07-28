# Development Plan P2 — Persistent ACME Accounts and Sectigo EAB

## Objective

Add production-grade ACME account lifecycle management and full Sectigo External Account Binding support.

## Key Outcome

CertDiscovery must be able to register once with Sectigo, securely persist the account identity, reuse it for issuance and renewal, and avoid opening a new ACME account for every request.

## Work Items

### P2.1 — Add Sectigo Provider Type

Extend:

```csharp
AcmeProviderType
```

Add:

```text
Sectigo
```

Do not hardcode Sectigo URLs. Continue to support custom directory URLs.

### P2.2 — Add ACME Account Entity

Create:

```text
AcmeAccount
- Id
- AcmeProviderId
- AccountLocation
- AccountKeySecretReference
- ExternalAccountBindingKeyId
- Status
- ContactEmail
- CreatedAtUtc
- UpdatedAtUtc
- LastUsedAtUtc
- DeactivatedAtUtc
```

Relationships:

```text
AcmeProvider 1 -> N AcmeAccount
AcmeCertificateRequest N -> 1 AcmeAccount
```

### P2.3 — Add Secret Reference Model

Do not persist the account key or EAB HMAC as plaintext in the account entity.

Temporary compatibility:

- Existing plaintext values may be migrated.
- New writes must use secret references.
- UI must never return secret values after save.

### P2.4 — Implement EAB Registration

Enhance the ACME client to support:

- EAB Key ID
- EAB HMAC key
- Base64/base64url normalization
- HMAC algorithm required by ACME library
- Actionable error mapping
- Account registration retry
- Existing account reuse

### P2.5 — Account Reuse

Issuance flow:

```text
Load provider
  -> Load active account
  -> Retrieve account key from secret provider
  -> Resume ACME account
  -> Create order
```

Registration flow:

```text
No active account
  -> Register account with optional EAB
  -> Store account key securely
  -> Store account location
```

### P2.6 — Sectigo Integration UI

Add fields:

- Provider type
- Directory URL
- Account email
- EAB Key ID
- EAB HMAC secret
- Staging/production
- Notes

Add actions:

- Test directory
- Register account
- Test account
- Disable account
- Rotate account key, if supported
- Show last successful use

Never display saved HMAC or account key.

### P2.7 — Sectigo Certificate Metadata

Add optional provider metadata:

```text
Organization
Department
CertificateProfile
ProductType
AllowedDomainPattern
```

Initial scope:

- DV
- Standard SAN certificate
- Wildcard
- DNS-01

Defer advanced OV workflow until Sectigo account/profile behavior is verified.

### P2.8 — Renewal Compatibility

Existing scheduled renewal must:

- Reuse the same ACME account
- Recreate a fresh order
- Rotate certificate private key according to policy
- Preserve request history
- Store new certificate version
- Not overwrite audit history

## Tests

Required:

- EAB account registration success
- Invalid key ID
- Invalid HMAC
- Reuse existing account
- Register only once across multiple requests
- Scheduled renewal uses same account
- Generic ACME without EAB still works
- Let’s Encrypt existing behavior remains valid
- Secret values are never returned by DTOs
- Sectigo provider can be disabled

## Acceptance Criteria

- [ ] Sectigo provider exists.
- [ ] EAB registration works.
- [ ] ACME accounts are persistent.
- [ ] Renewal does not create a new account each time.
- [ ] Account keys are stored through secret references.
- [ ] Existing non-EAB providers still work.
- [ ] Provider test UI exists.
- [ ] Audit records identify provider and account.
- [ ] Documentation includes Sectigo setup instructions.

## VibeCode Prompt

```text
Add persistent ACME account lifecycle management to CertDiscovery.

Create an AcmeAccount entity linked to AcmeProvider and certificate requests.
Implement External Account Binding using the existing provider EAB Key ID and
HMAC fields. Add Sectigo as an AcmeProviderType.

The application must register an account only when no active account exists,
securely store the account key through a secret reference, resume the account
for future orders, and reuse it during scheduled renewal.

Preserve generic ACME and Let's Encrypt behavior. Add integration tests for EAB
success, invalid credentials, account reuse, and renewal.
```
