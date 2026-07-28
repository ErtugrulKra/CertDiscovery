# Secret Inventory Baseline

| Sensitive value | Current location | Classification | Production action |
|---|---|---|---|
| ACME account key | `AcmeCertificateRequest.AcmeAccountKeyPem` | Plaintext DB | Move to secret reference |
| Certificate private key | `AcmeCertificateRequest.CertificatePrivateKeyPem` and Vault KV | Plaintext DB and Vault | Remove DB copy after secure storage |
| EAB HMAC key | `AcmeProvider.ExternalAccountBindingHmacKey` | Plaintext DB | Move to secret reference |
| EAB key ID | `AcmeProvider.ExternalAccountBindingKeyId` | Plaintext DB | Treat as sensitive metadata |
| Cloudflare API token | `DnsProvider.ApiToken` | Plaintext DB | Move to secret reference |
| Vault token | `VaultServer.Token` | Plaintext DB | Use workload identity or secret reference |
| Worker API key | environment/appsettings | Environment variable; development default | Rotate and supply from secret manager |
| Cookie signing/data-protection keys | configured filesystem path | Generated runtime value | Persist securely with restricted access |
| Application database | SQLite volume/file | Not yet protected | Encrypt storage and restrict filesystem access |
| Future AWS credentials | Not implemented | Not yet protected | Prefer workload identity; otherwise secret reference |
| Future Azure credentials | Not implemented | Not yet protected | Prefer managed/workload identity |

DTOs expose only boolean indicators for saved Vault and integration tokens, but
the application entities and SQLite database contain the plaintext values above.
Logs and exception messages must never include these values.

