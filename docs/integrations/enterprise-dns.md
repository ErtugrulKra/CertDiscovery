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

### Minimum Route53 permissions

Scope `route53:ChangeResourceRecordSets`, `route53:GetHostedZone` and
`route53:ListResourceRecordSets` to the hosted zone used by CertDiscovery.
Zone discovery and change propagation additionally require
`route53:ListHostedZonesByName` and `route53:GetChange`. A minimal IAM policy
can use the following actions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "route53:GetHostedZone",
        "route53:ListResourceRecordSets",
        "route53:ChangeResourceRecordSets"
      ],
      "Resource": "arn:aws:route53:::hostedzone/HOSTED_ZONE_ID"
    },
    {
      "Effect": "Allow",
      "Action": [
        "route53:ListHostedZonesByName",
        "route53:GetChange"
      ],
      "Resource": "*"
    }
  ]
}
```

When `HostedZoneId` is configured, zone-name discovery is skipped. Assume-role
trust policy configuration remains the responsibility of the AWS account.

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

### Minimum Azure DNS permissions

Assign access at the individual DNS zone scope. The built-in `DNS Zone
Contributor` role is supported. For a narrower custom role, allow:

- `Microsoft.Network/dnsZones/read`
- `Microsoft.Network/dnsZones/TXT/read`
- `Microsoft.Network/dnsZones/TXT/write`
- `Microsoft.Network/dnsZones/TXT/delete`

The identity does not need access to unrelated subscriptions, resource groups,
zones or Azure Key Vault secrets. Service-principal secrets are stored by
CertDiscovery's protected secret provider; managed identity and workload
identity modes require no stored Azure client secret.

## Verification

Use **Test DNS** on the Integrations page. The test verifies credentials and
zone access, creates a uniquely named temporary TXT value, waits for it on the
zone's authoritative name servers, and cleans it up. The latest health status
and any actionable error are displayed without credential values.
