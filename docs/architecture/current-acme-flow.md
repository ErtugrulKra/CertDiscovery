# Current ACME Flow

## Request Creation

1. Validate the domain, provider, Vault server and optional schedule.
2. Normalize the primary domain and SANs to lower case without trailing dots.
3. For wildcard requests, store `*.example.com` as the primary name and add the
   base name to SANs.
4. Persist a `Draft` request.

## DNS-01 Challenge

1. `Draft` or `Failed` moves to challenge creation.
2. A new ES256 ACME account key and ACME account are created for every challenge.
3. A new order is created for the primary name and all SANs.
4. Each authorization becomes `_acme-challenge.<identifier>` plus its DNS value.
5. Account key, order URL and newline-delimited challenge pairs are persisted.
6. Status becomes `PendingDns`.
7. With no DNS provider, the operator publishes the displayed records manually.
8. With Cloudflare, exact challenge values are published and publication metadata
   is recorded.

## Validation, Issue and Storage

1. `PendingDns`, `ReadyToValidate` or `Failed` becomes `Validating`.
2. The persisted account key and order URL resume the Certes order.
3. Non-valid DNS challenges are submitted and the order is polled for readiness.
4. A fresh ES256 certificate key and CSR are generated.
5. Leaf, chain and private key are temporarily persisted on the request.
6. Inventory is upserted by SHA-256 fingerprint, including SAN and chain rows.
7. The certificate bundle is written to Vault KV v2.
8. Status becomes `StoredInVault`, then matching Cloudflare TXT values are
   cleaned up.

## Failure and Retry Semantics

| Condition | Result |
|---|---|
| Order/authorization timeout | `ReadyToValidate`; order remains retryable |
| Other validation or storage error | `Failed`; error text is persisted |
| DNS publication error | Request state is retained; DNS publish status is `Failed` |
| Cleanup error after issuance | Issuance remains successful; cleanup error is recorded |
| Scheduled ACME/DNS validation failure | Matching TXT values are cleaned and retry is set for 15 minutes |

