# Sectigo ACME with External Account Binding

CertDiscovery supports Sectigo and other ACME services that require External
Account Binding (EAB). The directory URL is always supplied by the operator and
is not hardcoded.

## Configuration

1. Obtain the ACME directory URL, EAB Key ID and EAB HMAC key from Sectigo.
2. Open **Integrations**, create an ACME provider and select **Sectigo**.
3. Enter the directory URL, account email, EAB credentials and optional
   organization/profile metadata.
4. Save the provider. The HMAC value is encrypted immediately and is never
   returned to the browser again.
5. Use **Test directory** to verify directory access.
6. Use **Register account** once. CertDiscovery stores the account key through a
   protected secret reference and reuses the account for future orders.
7. Use **Test account** to verify that the stored key resolves to the same ACME
   account location.

Disabling an account prevents it from being used. A later certificate request
can register a new active account after credentials are reviewed.

## Supported Initial Scope

- Domain Validation (DV)
- Standard and SAN certificates
- Wildcard certificates
- DNS-01 validation
- Scheduled renewal with the same ACME account and a fresh certificate key

Advanced organization-validation workflows depend on the Sectigo profile and
are outside the initial scope.

## Secret Handling

EAB HMAC keys and ACME account private keys are stored as encrypted
`SecretRecord` values protected by ASP.NET Core Data Protection. Domain entities
and public DTOs contain opaque references or boolean configuration indicators,
never the secret value. Existing plaintext EAB HMAC values are migrated to
protected records at application startup after the P2 database migration.

Existing in-progress ACME orders may temporarily retain their legacy request
account key until that order completes. New orders never write an account key to
the certificate request row.

