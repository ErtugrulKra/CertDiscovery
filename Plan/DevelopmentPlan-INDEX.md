# CertDiscovery — Enterprise Certificate Lifecycle Roadmap

## Product Goal

Transform CertDiscovery from a discovery-first ACME platform into a complete, provider-independent Certificate Lifecycle Management and Orchestration platform.

The target product must exceed a conventional Sectigo ACME CaaS implementation by combining:

- Certificate discovery and inventory
- Generic ACME issuance
- Sectigo EAB support
- Cloudflare, AWS Route53 and Azure DNS DNS-01 automation
- Secure secret management
- Persistent ACME account lifecycle
- Automated renewal
- Deployment adapters
- Post-deployment verification
- Rollback
- Notifications and audit history
- Production-grade persistence and distributed execution

## Target Lifecycle

```text
Discover
  -> Inventory
  -> Request
  -> Authorize
  -> Issue
  -> Store
  -> Deploy
  -> Verify
  -> Monitor
  -> Renew
  -> Revoke
```

## Phase Order

| Phase | File | Objective |
|---|---|---|
| P0 | `DevelopmentPlan-P0-Baseline.md` | Freeze current behavior and establish technical baseline |
| P1 | `DevelopmentPlan-P1-Core-Refactoring.md` | Split ACME, DNS and storage responsibilities |
| P2 | `DevelopmentPlan-P2-Sectigo-EAB.md` | Add persistent ACME accounts and Sectigo EAB |
| P3 | `DevelopmentPlan-P3-DNS-Providers.md` | Add Route53 and Azure DNS providers |
| P4 | `DevelopmentPlan-P4-Deployer-Architecture.md` | Build deployment adapter architecture |
| P5 | `DevelopmentPlan-P5-Deployers-Verification.md` | Add deployers, verification and rollback |
| P6 | `DevelopmentPlan-P6-Enterprise-Readiness.md` | Add production, security, audit and scale features |
| P7 | `DevelopmentPlan-P7-Competitive-Advantage.md` | Add differentiating capabilities beyond Sectigo CaaS |

## Mandatory Execution Rules

1. Complete phases in order.
2. Do not implement Route53 or Azure DNS directly inside `CertificateRequestService`.
3. Do not add new plaintext credentials to the database.
4. Preserve existing Cloudflare, manual DNS-01, Vault storage and scheduled renewal behavior.
5. Every phase must end with:
   - passing .NET tests,
   - passing Python worker tests,
   - updated README,
   - migration review,
   - manual smoke test.
6. Every new provider must have contract tests.
7. Every deployer must implement precheck, deploy, verify and rollback behavior.
8. A phase is not complete until its acceptance checklist is fully checked.

## Definition of Product Success

The roadmap is complete when CertDiscovery can:

- Discover certificates from networks, assets, Vault and Kubernetes.
- Issue certificates from Let’s Encrypt, Sectigo and generic ACME servers.
- Use manual DNS, Cloudflare, Route53 and Azure DNS.
- Store secrets outside plaintext application tables.
- Schedule renewals centrally.
- Deploy certificates to multiple target types.
- Verify that the newly deployed certificate is actually being served.
- Roll back failed deployments.
- Notify operators and preserve a complete audit trail.
- Run with PostgreSQL and distributed workers.
- Support multi-tenant enterprise deployments.
