# Development Plan P1 — Core Refactoring and Provider Boundaries

## Objective

Break the monolithic certificate request workflow into replaceable services without changing existing behavior.

## Key Outcome

After P1, Cloudflare, Certes ACME and Vault must operate through interfaces. `CertificateRequestService` must become an orchestrator rather than an implementation container.

## Target Components

```text
CertificateRequestService
  -> IAcmeCertificateClient
  -> IDnsChallengeProviderResolver
  -> IDnsChallengeProvider
  -> ICertificateStore
  -> ICertificateInventoryWriter
  -> ICertificateRequestStateMachine
```

## Work Items

### P1.1 — Introduce ACME Contracts

Create:

```text
src/CertificateDiscovery.Application/Acme/
  IAcmeCertificateClient.cs
  AcmeChallengeResult.cs
  AcmeOrderContext.cs
  IssuedCertificateBundle.cs
  AcmeProblemDetails.cs
```

Interface responsibilities:

- Create or resume an order
- Return DNS challenges
- Validate authorizations
- Finalize CSR
- Return certificate, chain and private key
- Revoke certificate
- Normalize ACME errors

Implement:

```text
CertesAcmeCertificateClient
```

Move Certes-specific reflection and resource parsing out of `CertificateRequestService`.

### P1.2 — Introduce DNS Provider Contracts

Create:

```text
src/CertificateDiscovery.Application/Dns/
  IDnsChallengeProvider.cs
  IDnsChallengeProviderResolver.cs
  DnsTxtChallenge.cs
  DnsPublishResult.cs
  DnsPropagationResult.cs
```

Required operations:

```csharp
PublishAsync
WaitForPropagationAsync
CleanupAsync
ValidateConfigurationAsync
```

Implement:

```text
ManualDnsChallengeProvider
CloudflareDnsChallengeProvider
DnsChallengeProviderResolver
```

Move all Cloudflare HTTP code out of `CertificateRequestService`.

### P1.3 — Introduce Certificate Store Contracts

Create:

```text
src/CertificateDiscovery.Application/Storage/
  ICertificateStore.cs
  CertificateStoreContext.cs
  CertificateStoreResult.cs
```

Implement:

```text
VaultKvCertificateStore
```

Keep existing Vault KV path behavior.

### P1.4 — Extract Inventory Persistence

Create:

```text
ICertificateInventoryWriter
CertificateInventoryWriter
```

Responsibilities:

- Parse X.509 metadata
- Upsert by fingerprint
- Write SANs
- Write chain entries
- Associate ACME source
- Return certificate ID

### P1.5 — Add Request State Machine

Create:

```text
ICertificateRequestStateMachine
CertificateRequestStateMachine
```

Rules must explicitly define legal transitions:

```text
Draft -> PendingDns
PendingDns -> ReadyToValidate
ReadyToValidate -> Validating
Validating -> Issued
Issued -> StoredInVault
Any active state -> Failed
Failed -> PendingDns
```

Reject invalid transitions centrally.

### P1.6 — Reduce CertificateRequestService

Target responsibilities:

- Validate command
- Load aggregate
- Call ACME client
- Call DNS provider
- Call store
- Update state
- Save transaction

Target size:

```text
Preferably below 350 lines
```

### P1.7 — Dependency Injection Registration

Create extension methods:

```text
AddAcmeServices()
AddDnsChallengeProviders()
AddCertificateStores()
```

Do not use provider `switch` statements in controllers or request services.

## Migration Notes

No schema migration should be required unless state transition history is introduced.

## Tests

- Existing P0 tests must remain unchanged and pass.
- Add contract tests for Cloudflare provider.
- Add ACME client tests with fake ACME server.
- Add state-machine transition tests.
- Add resolver test for unsupported provider.
- Add Vault store contract tests.

## Acceptance Criteria

- [ ] No Cloudflare API code remains in `CertificateRequestService`.
- [ ] No Certes implementation detail remains in `CertificateRequestService`.
- [ ] Vault storage is behind `ICertificateStore`.
- [ ] ACME and DNS provider selection uses DI/resolver.
- [ ] Existing UI behavior is unchanged.
- [ ] Existing renewal behavior is unchanged.
- [ ] All P0 tests pass.
- [ ] New contract tests pass.
- [ ] README architecture section is updated.

## VibeCode Prompt

```text
Refactor CertDiscovery so that CertificateRequestService becomes an orchestration
service.

Extract Certes ACME logic into IAcmeCertificateClient and
CertesAcmeCertificateClient. Extract Cloudflare and manual DNS behavior into
IDnsChallengeProvider implementations. Extract Vault KV storage into
ICertificateStore and certificate inventory persistence into
ICertificateInventoryWriter.

Introduce an explicit certificate request state machine. Preserve all existing
behavior and routes. Do not add Route53, Azure DNS or Sectigo yet.

Use dependency injection and provider resolvers instead of switch statements.
Run all existing and new tests after each extraction.
```
