<p align="center">
  <img src="docs/images/certdiscovery-logo.png"
       alt="CertDiscovery"
       width="600">
</p>

<p align="center">
  <strong>
    Open-source TLS certificate discovery and lifecycle management.
  </strong>
</p>

<p align="center">
  Discover every certificate before it becomes an outage.
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#roadmap">Roadmap</a>
</p>

<p align="center">
  <a href="https://github.com/ErtugrulKra/CertDiscovery/actions/workflows/ci.yml"><img src="https://github.com/ErtugrulKra/CertDiscovery/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/.NET-8.0-512BD4" alt=".NET 8">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT">
</p>

<p align="center">
  <img src="docs/images/dashboard.png"
       alt="CertDiscovery Dashboard"
       width="1000">
</p>

## Why CertDiscovery?

TLS certificate management is becoming an automation problem.

As certificate lifetimes continue to shrink, manual inventories,
renewal spreadsheets, and undocumented endpoints become increasingly risky.

CertDiscovery follows a simple principle:

> **Discovery first. Automation second.**

Before you can automate certificate renewal, you need to know:

- Which certificates exist
- Where they are deployed
- When they expire
- Which systems depend on them

CertDiscovery provides a centralized view of your certificate estate
and the automation foundation required to manage it.

> **You can't automate certificates you don't know exist.**

## Built for the shorter TLS certificate era

Certificate lifecycle management is becoming an automation problem.

<p align="center">
  <strong>398 days</strong><br>
  ↓<br>
  <strong>200 days</strong><br>
  ↓<br>
  <strong>100 days</strong><br>
  ↓<br>
  <strong>47 days</strong>
</p>

Manual certificate inventories and renewal processes won't scale.

TLS certificate lifetimes are getting shorter. CertDiscovery helps you discover
certificates across your infrastructure, build a centralized inventory, monitor
expiration, and automate certificate lifecycle operations.

## See CertDiscovery in action

### Dashboard

See certificate health, upcoming expirations, managed assets, and recent scan
activity from a single operational view. The dashboard shown above gives teams an
immediate view of their current TLS risk.

### Certificate Inventory

Build a searchable source of truth for certificate ownership, validity, issuer,
fingerprints, SANs, certificate chains, and the assets where each certificate is
used.

<p align="center">
  <img src="docs/images/certificates.png"
       alt="CertDiscovery Certificate Inventory"
       width="1000">
</p>

### Network Discovery

Scan CIDR ranges to uncover TLS endpoints that are missing from the known asset
inventory, inspect their certificates, and promote discovered endpoints into
managed assets.

<p align="center">
  <img src="docs/images/network-discovery.png"
       alt="CertDiscovery Network Discovery"
       width="1000">
</p>

## Features

- **Asset-based TLS scanning** — HTTPS, TLS, SMTPS, IMAPS, POP3S, LDAPS with scheduled and manual scans
- **Network range discovery** — CIDR-based TCP+TLS probing with endpoint promotion to assets
- **Certificate inventory** — fingerprinting, SAN parsing, chain entries, expiration tracking
- **Web dashboard** — assets, certificates, scan jobs, worker status, and alert thresholds
- **REST API + Swagger** — full programmatic access at `/swagger`
- **Python asyncio workers** — concurrent discovery via API-key-protected job polling
- **Vault integration** — import from public TLS endpoints, PKI mounts, and KV v2 secrets
- **ACME issuance** — DNS-01 validation with manual or Cloudflare-automated TXT publishing
- **Scheduled ACME renewal** — threshold-based renewal with Vault KV storage
- **Observability** — Prometheus `/metrics` and OpenTelemetry instrumentation
- **Role-based access** — Admin and Read roles with cookie authentication

## Quick Start

### Prerequisites

- Docker Desktop

### Run with Docker Compose

```bash
git clone https://github.com/ErtugrulKra/CertDiscovery.git
cd CertDiscovery
docker compose up --build
```

| Service | URL |
|---------|-----|
| Web UI | http://localhost:8080 |
| Swagger | http://localhost:8080/swagger |
| Prometheus metrics | http://localhost:8080/metrics |
| Dev Vault (Compose only) | http://localhost:8200 |

On first startup, a default admin user is created:

```text
User name: Admin
Password: Admin123
```

Change this password or disable the account after creating a new Admin user.

Compose reads [`.env.example`](.env.example) by default. For production-like usage, copy it to `.env`, change the secret values, and update the `env_file` entry in [`docker-compose.yml`](docker-compose.yml) to `.env`.

The SQLite database is stored on the `certificate_sqlite` named volume mounted into the `certificate-web` container.

## Architecture

<p align="center">
  <img src="docs/images/certdiscovery-architecture.png"
       alt="CertDiscovery Architecture"
       width="100%">
</p>

CertDiscovery follows a discovery-first architecture.

- Infrastructure assets and network ranges are scanned by Python workers.
- Discovery results are submitted through the REST API.
- Certificates are normalized into a centralized inventory.
- ACME and DNS integrations automate issuance and renewal.
- HashiCorp Vault can be used for certificate storage and discovery.
- Prometheus and OpenTelemetry provide operational visibility.

> **Discovery first. Automation second.**

## Development Setup

### Prerequisites

- .NET SDK 8 or 9
- Python 3.12 recommended (3.11 also works for local tests)
- Docker Desktop (optional, for full stack)

### Web application

```bash
dotnet restore CertificateDiscovery.sln --configfile NuGet.Config
dotnet run --project src/CertificateDiscovery.Web/CertificateDiscovery.Web.csproj
```

The port may differ depending on `launchSettings.json` or console output.

### Python worker

```bash
cd workers/certificate-discovery-worker
python -m venv .venv

# Linux/macOS
source .venv/bin/activate
pip install -r requirements.txt
export WORKER_API_BASE_URL=http://localhost:5080
export WORKER_API_KEY=dev-worker-key-change-me
python -m worker.main

# Windows PowerShell
.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:WORKER_API_BASE_URL="http://localhost:5080"
$env:WORKER_API_KEY="dev-worker-key-change-me"
.venv\Scripts\python.exe -m worker.main
```

### Network range discovery worker

```bash
export WORKER_API_BASE_URL=http://localhost:5080
export WORKER_API_KEY=dev-worker-key-change-me
export WORKER_NAME=certificate-range-worker-local
python -m worker.range_main
```

### Database migrations

The EF Core tool manifest is included in [`.config/dotnet-tools.json`](.config/dotnet-tools.json).

```bash
dotnet tool restore
dotnet tool run dotnet-ef migrations add MigrationName --project src/CertificateDiscovery.Infrastructure --startup-project src/CertificateDiscovery.Web --output-dir Persistence/Migrations
dotnet tool run dotnet-ef database update --project src/CertificateDiscovery.Infrastructure --startup-project src/CertificateDiscovery.Web
```

In development, if `CertificateDiscovery:ApplyMigrationsOnStartup=true`, the application applies migrations during startup. Disable this in production through configuration.

## Configuration

Core worker environment variables:

| Variable | Description |
|----------|-------------|
| `WORKER_API_BASE_URL` | Base URL of the web API |
| `WORKER_API_KEY` | Shared API key for worker authentication |
| `WORKER_NAME` | Worker identifier for heartbeat and job claiming |
| `WORKER_MAX_CONCURRENCY` | Maximum concurrent scan tasks |
| `WORKER_POLL_INTERVAL_SECONDS` | Job polling interval |
| `WORKER_REQUEST_TIMEOUT_SECONDS` | Per-scan timeout |

See [`.env.example`](.env.example) for the full list including scheduler, OpenTelemetry, and range worker settings.

Supported worker protocols: `HTTPS`, `TLS`, `SMTPS`, `IMAPS`, `POP3S`, `LDAPS`.

## API Overview

Interactive API documentation is available at `/swagger` when the web application is running.

Key endpoints:

- **Assets** — `GET/POST/PUT/DELETE /api/assets`, `POST /api/assets/{id}/scan`
- **Certificates** — `GET /api/certificates`, `GET /api/certificates/{id}/assets`
- **Scan jobs** — `GET/POST /api/scan-jobs`
- **Workers** — `GET /api/workers/jobs/next`, `POST /api/workers/heartbeat`, `POST /api/workers/scan-results`
- **Metrics** — `GET /metrics`

Worker endpoints require the `X-Worker-Api-Key` header.

## Security

> **Important:** This application performs outbound TLS connections to user-controlled host/port values. Treat SSRF risk seriously in production deployments.

- Change the default `Admin/Admin123` credentials immediately after first login.
- Provide the worker API key through environment variables — never embed it in source code.
- ACME private keys and DNS provider API tokens are stored in the local SQLite database in this MVP. Use encrypted storage or external secret references before production use.
- Raw PEM data is not shown in UI lists; it is stored in the database.
- For production: enable HTTPS, configure cookie policy, rotate secrets, add audit logging, and apply private network allowlist/denylist controls for worker outbound connections.
- The Docker Compose Vault service runs in dev mode with a `root` token. Do not use this configuration in production.

## Authentication and Roles

The application uses cookie authentication with PBKDF2-SHA256 password hashing.

| Role | Permissions |
|------|-------------|
| `Admin` | Full access: assets, scans, users, integrations, network discovery, certificate requests |
| `Read` | View-only access to Dashboard, Assets, Certificates, and Scan Jobs |

Users are created by an Admin from the `/Users` screen.

## Testing

```bash
dotnet test CertificateDiscovery.sln
```

Python worker tests:

```bash
cd workers/certificate-discovery-worker
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
PYTHONPATH=. python -m pytest tests -q
```

## Advanced Topics

### Network Range Discovery

UI path: `/NetworkDiscovery`

Example job configuration:

```text
Name: Datacenter edge scan
CIDR: 10.10.0.0/24
Ports: 443,8443,9443,465,993,995,636
TimeoutSeconds: 3
MaxConcurrency: 100
```

For safety, the IPv4 CIDR prefix is limited to `/16` through `/32`. The range worker performs a TCP+TLS attempt for every IP/port combination. Discovered endpoints can be promoted to normal Assets by an Admin.

Notes:

- Because connections are made by IP address, SNI may be unknown. Reverse DNS is tried when available.
- STARTTLS ports are not included in the first version of this module.
- For large ranges, choose timeout and concurrency values carefully.

### Vault and ACME Integrations

Manage integrations at `/Integrations`. Issue certificates at `/CertificateRequests`.

**Vault actions:**

- `Scan TLS` — import the public TLS certificate from a Vault server endpoint
- `Import PKI` — import certificates from a HashiCorp Vault PKI mount
- Vault KV discovery — scan KV v2 secrets at `/VaultDiscovery`

**ACME DNS-01 workflow:**

1. Create an ACME provider (start with Let's Encrypt Staging).
2. Create a Vault integration (Compose dev Vault: `http://vault:8200`, token `root`).
3. Optionally create a Cloudflare DNS provider for automatic TXT publishing.
4. Create a certificate request with domain, SANs, and Vault KV path.
5. Start the challenge, publish TXT records (automatic or manual), validate, issue, and store in Vault.

Example DNS provider:

```text
Name: Cloudflare example.com
Provider type: Cloudflare
DNS zone: example.com
API token: Cloudflare token with Zone:Read and DNS:Edit permissions
Enabled: enabled
```

Example certificate request:

```text
Primary domain: example.com
Subject Alternative Names: www.example.com
DNS provider: Cloudflare example.com, or Manual TXT only
Vault KV secret path: secret/certificates/example.com
```

**Scheduled ACME renewal:** Enable `ScheduleCheck` on a certificate request with a validity threshold (default 5 days) and CRON expression (default `0 0 * * *`). The built-in renewal worker handles challenge recreation, DNS publishing, issuance, Vault storage, and TXT cleanup.

### Observability

Prometheus metrics at `/metrics` include:

- `certificate_discovery_certificate_not_after_timestamp_seconds`
- `certificate_discovery_certificate_expires_in_days`
- `certificate_discovery_certificate_expired`
- `certificate_discovery_certificate_chain_entries`
- `certificate_discovery_certificate_status_total`

OpenTelemetry export:

```text
CertificateDiscovery__OpenTelemetry__ServiceName=certificate-discovery
CertificateDiscovery__OpenTelemetry__OtlpEndpoint=http://otel-collector:4317
```

### Adding a New Protocol Adapter

1. Add the protocol to the `AssetProtocol` enum in the Domain project.
2. Add it to the worker `SUPPORTED_PROTOCOLS` list.
3. For protocols requiring pre-handshake negotiation (e.g. STARTTLS), add an adapter in `discovery.py`.
4. Add successful and error-mapping scenarios to worker tests.

## Known Limitations

- Certificate chain entries depend on worker runtime peer chain retrieval.
- STARTTLS protocols are an extension point, not yet implemented.
- Worker health uses a heartbeat model instead of a worker HTTP endpoint.
- Private network allowlisting for SSRF mitigation is not yet implemented.
- Test coverage covers core domain, service, health, and parser tests; full integration scenarios are not yet automated.

## Roadmap

- STARTTLS adapters
- Certificate chain analysis
- OCSP/CRL checking
- Notification system (Email, Teams, Slack)
- Additional DNS provider integrations
- PostgreSQL and RabbitMQ backends
- Multi-tenancy
- Kubernetes deployment manifests

## License

This project is licensed under the [MIT License](LICENSE).
