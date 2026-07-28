# Secret Inventory Baseline

| Sensitive value | Current location | Classification | Production action |
|---|---|---|---|
| ACME account key | Protected `SecretRecord`, referenced by `AcmeAccount` | Encrypted DB secret reference | Legacy in-progress orders remain compatible |
| Certificate private key | `AcmeCertificateRequest.CertificatePrivateKeyPem` and Vault KV | Plaintext DB and Vault | Remove DB copy after secure storage |
| EAB HMAC key | Protected `SecretRecord`, referenced by `AcmeProvider` | Encrypted DB secret reference | Rotate through the integration form |
| EAB key ID | `AcmeProvider.ExternalAccountBindingKeyId` | Plaintext DB | Treat as sensitive metadata |
| Cloudflare API token | `DnsProvider.ApiTokenSecretReference` | Protected secret reference | Legacy plaintext values migrate at startup |
| AWS access/secret/session credentials | `DnsProvider.*SecretReference` | Protected secret reference | Optional; default/workload credentials are preferred |
| Azure service-principal client secret | `DnsProvider.ClientSecretReference` | Protected secret reference | Optional; managed/workload identity is preferred |
| Deployment target credential | `DeploymentTarget.SecretReference` | Protected secret reference | Never returned by deployment DTOs |
| PKCS#12 password | Runtime/secret provider input | Runtime only | PFX conversion is in-memory; no temporary file is created |
| Vault token | `VaultServer.Token` | Plaintext DB | Use workload identity or secret reference |
| Worker API key | environment/appsettings | Environment variable; development default | Rotate and supply from secret manager |
| Cookie signing/data-protection keys | configured filesystem path | Generated runtime value | Persist securely with restricted access |
| Application database | SQLite volume/file | Not yet protected | Encrypt storage and restrict filesystem access |
| Future AWS credentials | Not implemented | Not yet protected | Prefer workload identity; otherwise secret reference |
| Future Azure credentials | Not implemented | Not yet protected | Prefer managed/workload identity |

DTOs expose only boolean indicators for saved Vault and integration tokens, but
the application entities and SQLite database contain the plaintext values above.
Logs and exception messages must never include these values.
