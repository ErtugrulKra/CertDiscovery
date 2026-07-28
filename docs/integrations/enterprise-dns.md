# Enterprise DNS providers

CertDiscovery supports manual DNS-01, Cloudflare, AWS Route53 and Azure DNS.
Automated providers preserve unrelated TXT values, publish multiple challenge
values idempotently, verify authoritative DNS propagation and remove only the
values created for the current certificate request.

## AWS Route53

Configure the DNS zone and, when duplicate public/private zones exist, an
explicit hosted zone ID. Authentication modes are:

- Default AWS credential chain
- Assume role (role ARN required)
- Workload identity / EKS IRSA
- Static access key, secret key and optional session token

Static credentials are encrypted through the application secret provider and
are never returned by the integration API or UI.

## Azure DNS

Configure subscription ID, resource group and DNS zone. Authentication modes
are:

- `DefaultAzureCredential`
- Managed Identity
- Workload Identity
- Service principal

Service-principal client secrets are encrypted through the application secret
provider. Azure record updates use ETags to avoid overwriting concurrent
changes.

## Verification

Use **Test DNS** on the Integrations page. The test verifies credentials and
zone access, creates a uniquely named temporary TXT value, waits for it on the
zone's authoritative name servers, and cleans it up. The latest health status
and any actionable error are displayed without credential values.
