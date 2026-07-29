# CertDiscovery Complete User Guide

This guide explains how to install, use, manage, and understand CertDiscovery. It is written for certificate administrators, infrastructure teams, security teams, and developers. The language is simple and practical, but the guide also explains the important technical details.

> CertDiscovery follows one main idea: **discover first, automate second**. You need to know where your certificates are before you can manage them safely.

## Table of contents

1. [What CertDiscovery does](#1-what-certdiscovery-does)
2. [Main concepts](#2-main-concepts)
3. [Quick start with Docker](#3-quick-start-with-docker)
4. [First login and user roles](#4-first-login-and-user-roles)
5. [A recommended first-day setup](#5-a-recommended-first-day-setup)
6. [Dashboard](#6-dashboard)
7. [Assets](#7-assets)
8. [Scan jobs and certificate discovery workers](#8-scan-jobs-and-certificate-discovery-workers)
9. [Certificate inventory](#9-certificate-inventory)
10. [Network Discovery](#10-network-discovery)
11. [Vault integrations and Vault Discovery](#11-vault-integrations-and-vault-discovery)
12. [ACME providers and accounts](#12-acme-providers-and-accounts)
13. [DNS providers](#13-dns-providers)
14. [Certificate requests, issuance, and renewal](#14-certificate-requests-issuance-and-renewal)
15. [Certificate deployments](#15-certificate-deployments)
16. [Microsoft IIS deployment agent](#16-microsoft-iis-deployment-agent)
17. [Users, workers, and application settings](#17-users-workers-and-application-settings)
18. [REST API](#18-rest-api)
19. [Monitoring, health, and metrics](#19-monitoring-health-and-metrics)
20. [Architecture explained in simple language](#20-architecture-explained-in-simple-language)
21. [Data, secrets, and security](#21-data-secrets-and-security)
22. [Backup, upgrade, and daily operations](#22-backup-upgrade-and-daily-operations)
23. [Troubleshooting](#23-troubleshooting)
24. [Known limits](#24-known-limits)
25. [Glossary](#25-glossary)

---

## 1. What CertDiscovery does

CertDiscovery gives you one place to see and manage TLS certificates.

You can use it to:

- define known TLS endpoints as assets;
- scan HTTPS, TLS, SMTPS, IMAPS, POP3S, and LDAPS endpoints;
- find unknown TLS endpoints inside an IPv4 CIDR range;
- collect certificate subjects, issuers, serial numbers, fingerprints, SANs, validity dates, and chain entries;
- see which assets use the same certificate;
- monitor certificate health and expiration;
- import certificates from HashiCorp Vault public endpoints, PKI mounts, and KV v2 secrets;
- request certificates from an ACME service with DNS-01 validation;
- publish DNS challenges manually or through Cloudflare, AWS Route53, or Azure DNS;
- renew managed certificates on a schedule;
- keep managed certificate material in Vault;
- deploy certificates to supported local, server, Kubernetes, AWS, Azure, Vault, and IIS targets;
- verify a deployment from one or more endpoints;
- retry, approve, cancel, reject, or roll back deployments;
- use distributed Python workers for scans;
- monitor health, metrics, workers, and Windows deployment agents.

CertDiscovery has two related areas:

- **Discovery and inventory** answer: “What certificates do we have, and where are they?”
- **Lifecycle management** answers: “How do we issue, store, renew, deploy, and verify a managed certificate?”

---

## 2. Main concepts

Understanding these names makes the rest of the application much easier.

### Asset

An asset is a known endpoint that CertDiscovery should scan. For example:

```text
Name: Customer portal
Host: portal.example.com
Port: 443
Protocol: HTTPS
Environment: Production
```

An asset is not the certificate itself. It is the place where a certificate is used.

### Scan job

A scan job is a unit of work for one or more assets. A Python worker claims the job, connects to the endpoints, reads the public certificates, and sends the result back.

### Certificate

A certificate is a normalized inventory record. CertDiscovery uses the SHA-256 fingerprint to identify and de-duplicate it. One certificate can be linked to several assets.

### Network discovery job

A network discovery job checks IP address and port combinations in an IPv4 CIDR range. It helps you find TLS endpoints that are not yet known as assets.

### Vault server

A Vault server integration can be used for discovery and for managed certificate storage. Vault KV v2 is the source of truth for managed certificate bundles that include a private key.

### ACME provider and ACME account

The provider contains the ACME directory address and organization settings. The account is the reusable identity and private account key used to communicate with that ACME service.

### DNS provider

A DNS provider publishes and removes `_acme-challenge` TXT values. It can also wait for authoritative DNS propagation before validation.

### Certificate request

A certificate request keeps the state of an ACME order, its DNS challenge, its resulting inventory certificate, its Vault location, and its renewal schedule.

### Deployment target

A target describes where and how a managed certificate will be installed. Target configuration is stored as JSON. Credentials are stored separately through the protected secret system.

### Deployment policy

A policy controls approval, retry, rollback, verification, and automatic deployment behavior.

### Deployment

A deployment joins one stored certificate request, one target, and one policy. Its complete history is kept as audit events.

### Worker and deployment agent

A **Python worker** scans certificates or IP ranges. A **Windows deployment agent** installs certificates on Microsoft IIS. They are different programs with different permissions.

---

## 3. Quick start with Docker

### Requirements

- Git
- Docker Desktop or another working Docker Engine
- free local ports `8080` and `8200`

### Start the complete development stack

```powershell
git clone https://github.com/ErtugrulKra/CertDiscovery.git
cd CertDiscovery
docker compose up --build -d
docker compose ps
```

Docker Compose starts four services:

| Service | Purpose |
|---|---|
| `certificate-web` | Web UI, API, database access, schedulers, ACME, and deployment orchestration |
| `certificate-worker` | Scans known assets |
| `certificate-range-worker` | Scans IPv4 CIDR ranges |
| `vault` | Development-only HashiCorp Vault |

Open these addresses:

| Function | Address |
|---|---|
| Web UI | `http://localhost:8080` |
| Swagger API page | `http://localhost:8080/swagger` |
| Prometheus metrics | `http://localhost:8080/metrics` |
| Liveness | `http://localhost:8080/health/live` |
| Readiness | `http://localhost:8080/health/ready` |
| Development Vault | `http://localhost:8200` |

Swagger is enabled in the Development environment. It may not be available in a production environment.

### First-start behavior

The web application does the following during startup:

1. It opens the configured SQLite database.
2. It applies EF Core migrations when `ApplyMigrationsOnStartup` is enabled.
3. It migrates supported legacy secrets into protected secret records.
4. It creates the first Admin user if needed.
5. In Development, it can also create development sample data.

The Compose database and Data Protection keys are stored in the `certificate_sqlite` Docker volume under `/data`.

### Stop or inspect the stack

```powershell
docker compose ps
docker compose logs certificate-web
docker compose logs certificate-worker
docker compose logs certificate-range-worker
docker compose down
```

`docker compose down` keeps named volumes by default. Do not add `-v` unless you really want to remove the stored database and key material.

### Important development warning

The Compose Vault uses development mode and the token `root`. The example worker API key and first Admin password are also public example values. Never use these values in production.

---

## 4. First login and user roles

The initial account is:

```text
User name: Admin
Password: Admin123
```

Log in, open the user menu in the top-right corner, and change this password immediately.

### Roles

| Role | Access |
|---|---|
| `Admin` | Full management of discovery, integrations, requests, deployments, agents, workers, users, and settings |
| `Read` | Read-only access to Dashboard, Assets, Certificates, and Scan Jobs |

Authentication uses a secure cookie with an eight-hour sliding lifetime. Passwords are hashed with PBKDF2-SHA256. A user who does not have enough permission sees the Access Denied page.

An Admin can create more users from **Users**. Give people the `Read` role when they only need inventory and health information.

---

## 5. A recommended first-day setup

For a new test system, use this order:

1. Change the default Admin password.
2. Open **Application Settings** and check expiration thresholds and scheduler settings.
3. Confirm that the asset worker and range worker are online.
4. Add one test asset and run a manual scan.
5. Check the result in **Scan Jobs** and **Certificates**.
6. Run a small **Network Discovery** job, such as a `/28` range.
7. Add a test Vault integration.
8. Add an ACME staging provider and register its account.
9. Add a DNS provider, then run its connection test.
10. Create a staging certificate request and store the result in Vault.
11. Create a safe deployment target and policy.
12. Test the target before starting a real deployment.

Starting small makes network, DNS, Vault, and permission errors easier to understand.

---

## 6. Dashboard

The Dashboard is the daily overview page. It shows:

- total assets;
- enabled assets;
- total certificates;
- expired, critical, warning, attention, and healthy certificate counts;
- certificates that will expire soon;
- recent scan jobs and their result;
- worker and inventory activity.

The health colors come from the expiration thresholds in **Application Settings**:

| Status | Meaning |
|---|---|
| `Expired` | The `Not After` time has passed |
| `Critical` | The certificate is inside the critical threshold |
| `Warning` | It is inside the warning threshold |
| `Attention` | It is inside the attention threshold |
| `Healthy` | It is outside all warning thresholds |

Use the Dashboard to decide what needs attention. Use the detail pages to find the reason.

---

## 7. Assets

Open **Assets** to manage known endpoints.

### Create an asset

Select **New asset** and complete the fields:

| Field | What it means |
|---|---|
| Name | Friendly name shown in the UI |
| Host | DNS name or IP address |
| Port | TCP port, for example `443` |
| Protocol | `HTTPS`, `TLS`, `SMTPS`, `IMAPS`, `POP3S`, or `LDAPS` |
| Description | Optional notes |
| Path | Optional application path for context |
| SNI host | TLS Server Name Indication value when it is different from Host |
| Environment | Development, Test, Staging, Production, or Other |
| Asset type | Web application, API, load balancer, reverse proxy, mail server, directory server, database, or Other |
| Owner | Team or person responsible for the endpoint |
| Enabled | Allows scheduled scanning |
| Scan interval | Minutes between scheduled scans |
| Timeout | Connection timeout in seconds |
| Tags | Optional labels for grouping and search |

Use an SNI host when you connect to an IP address or shared load balancer but need a specific virtual TLS host.

### Asset actions

From the asset list or detail page, an Admin can:

- create and edit an asset;
- enable or disable it;
- delete it;
- start a manual scan;
- view the last scan, next scan, and active certificate;
- inspect the certificate history connected to that asset.

Deleting an asset removes the managed endpoint record. It does not mean that the real server or its certificate is deleted.

### Filter assets

You can filter by:

- environment;
- protocol;
- asset type;
- owner;
- enabled state;
- certificates expiring within a number of days.

Useful examples:

- show enabled Production assets;
- show all mail protocols;
- show assets owned by the Platform team;
- show endpoints with a certificate expiring in 30 days.

### Manual and scheduled scans

Select **Scan** for an immediate scan. When the scheduler is enabled, CertDiscovery also creates jobs for enabled assets whose next scan time has arrived.

The scheduler controls job creation. The Python worker performs the network connection.

---

## 8. Scan jobs and certificate discovery workers

### Scan job flow

The normal flow is:

```text
Pending -> Running -> Completed
                     -> PartiallyCompleted
                     -> Failed
```

A retry creates or requeues work with the `Retry` trigger type. Jobs can also be marked `Cancelled`.

Each asset result is either `Success` or `Failed`. Common failure types are:

- DNS resolution failed;
- connection timeout;
- connection refused;
- TLS handshake failed;
- certificate parsing failed;
- unsupported protocol;
- internal worker error.

`PartiallyCompleted` means some assets succeeded and some failed.

### What the worker collects

For a successful TLS connection, the worker sends:

- leaf certificate data;
- SHA-256 fingerprint;
- subject and issuer;
- serial number;
- validity dates;
- signature and public-key information;
- SAN entries;
- available certificate chain entries;
- endpoint and timing information.

The server normalizes this data and links the certificate to the asset.

### Worker communication

The Python worker:

1. sends a heartbeat;
2. asks for the next job;
3. claims work;
4. scans several assets concurrently;
5. sends each result;
6. completes or fails the job;
7. waits for the next polling interval.

Worker API calls use the `X-Worker-Api-Key` header. Worker status is based on heartbeats:

- `Online`: recent heartbeat;
- `Stale`: heartbeat is late;
- `Offline`: heartbeat has been missing for longer.

### Run a worker outside Docker

```powershell
cd workers\certificate-discovery-worker
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:WORKER_API_BASE_URL="http://localhost:5080"
$env:WORKER_API_KEY="replace-with-your-key"
$env:WORKER_NAME="certificate-worker-local"
.venv\Scripts\python.exe -m worker.main
```

Important worker settings:

| Variable | Purpose |
|---|---|
| `WORKER_API_BASE_URL` | Central web/API address |
| `WORKER_API_KEY` | Shared worker authentication key |
| `WORKER_NAME` | Unique worker name |
| `WORKER_MAX_CONCURRENCY` | Number of scans that can run at the same time |
| `WORKER_POLL_INTERVAL_SECONDS` | Delay between job polls |
| `WORKER_REQUEST_TIMEOUT_SECONDS` | Per-request timeout |

Do not give two active workers the same name.

---

## 9. Certificate inventory

Open **Certificates** to search and inspect discovered certificates.

### Information in a certificate record

The list and detail pages can show:

- common name and subject;
- issuer;
- serial number;
- SHA-256 fingerprint;
- `Not Before` and `Not After` dates;
- days until expiration;
- health status;
- source;
- SAN values and their type: DNS, IP, Email, URI, or Other;
- signature algorithm;
- public-key algorithm and size;
- certificate chain entries;
- first and last seen times;
- linked assets and endpoint usage.

Certificate sources are:

- normal asset scan;
- network discovery;
- Vault public endpoint;
- Vault PKI;
- Vault KV;
- ACME.

### De-duplication and usage

The fingerprint is the certificate identity. If several assets return the same fingerprint, CertDiscovery keeps one certificate record and creates usage links to those assets.

This is useful for shared wildcard certificates and certificates behind several load balancers.

### Public inventory and managed certificates

There is an important difference:

- Discovery records describe public certificates seen on endpoints.
- Managed ACME certificates also have private key material and a versioned bundle.

For managed certificates, the private bundle stays in Vault. The database keeps metadata such as the fingerprint, lifecycle state, certificate ID, and Vault reference.

---

## 10. Network Discovery

Network Discovery finds TLS endpoints that are not already in the asset list.

### Create a discovery job

Open **Network Discovery**, select **New discovery**, and enter:

| Field | Meaning |
|---|---|
| Name | Friendly job name |
| CIDR | IPv4 network, from `/16` to `/32` |
| Ports | Comma-separated TCP ports |
| Timeout | Time allowed for each connection |
| Max concurrency | Maximum parallel endpoint checks |

Common ports are:

```text
443, 8443, 9443, 465, 993, 995, 636
```

Example:

```text
Name: Datacenter edge scan
CIDR: 10.10.20.0/24
Ports: 443,8443,9443
Timeout: 3 seconds
Max concurrency: 100
```

For safety and workload control, only IPv4 ranges from `/16` through `/32` are accepted. Begin with a small range.

### How range discovery works

The range worker tries each IP and port combination. It first checks the TCP connection, then tries a TLS handshake. Reverse DNS can help find a possible host name. Because the initial connection is often made by IP address, the worker may not know the correct SNI name.

The result records:

- address and port;
- detected host name when available;
- success or failure;
- certificate information;
- timing and error details;
- whether the endpoint was promoted.

### Promote an endpoint

After you check a result, select **Promote to asset**. CertDiscovery creates a normal asset so the endpoint can be scanned regularly.

Promotion is a review step. Do not automatically turn every open TLS port into a managed asset.

### Run a range worker outside Docker

```powershell
$env:WORKER_API_BASE_URL="http://localhost:5080"
$env:WORKER_API_KEY="replace-with-your-key"
$env:WORKER_NAME="certificate-range-worker-local"
$env:WORKER_MAX_CONCURRENCY="100"
.venv\Scripts\python.exe -m worker.range_main
```

Only scan networks where you have permission.

---

## 11. Vault integrations and Vault Discovery

### Add a Vault server

Open **Integrations**, select **New Vault server**, and enter:

| Field | Meaning |
|---|---|
| Name | Friendly integration name |
| Base URL | Vault address |
| Description | Optional notes |
| PKI mount path | For example `pki` |
| Token | Vault token, stored as a protected secret |
| Scan public endpoint | Allow import of the certificate served by the Vault HTTPS endpoint |
| Import PKI certificates | Allow import from the configured PKI mount |
| Enabled | Makes the integration available |

Editing a Vault server with an empty token keeps the current secret. Deleting the integration can affect requests and jobs that refer to it, so check dependencies first.

### Vault actions on the Integrations page

- **Scan public endpoint** connects to the Vault URL as a TLS endpoint and imports its public certificate.
- **Import PKI** reads certificates from the configured PKI mount and adds them to inventory.

The page keeps the last sync time, status, and error.

### Vault KV Discovery

Open **Vault Discovery** to inspect KV v2 content.

Create a job with:

| Field | Meaning |
|---|---|
| Name | Friendly job name |
| Vault server | Enabled Vault integration |
| KV mount path | KV v2 mount, usually `secret` |
| Base path | Starting folder inside the mount |
| Recursive | Also inspect child paths |
| Create assets | Create asset records where supported by discovered data |

Run the job and open its detail page. You can see:

- secrets checked;
- certificates found;
- assets created;
- failed secrets;
- duration and error message.

### Vault paths

A friendly path such as:

```text
secret/certificates/example.com
```

is written through the KV v2 data endpoint:

```text
/v1/secret/data/certificates/example.com
```

Each successful issue or renewal creates a new Vault version. This version history is also important for safe deployment and rollback.

### Production advice

Use a real Vault cluster with TLS, audit logging, backup, token policies, and limited paths. Do not use the Compose development Vault in production.

---

## 12. ACME providers and accounts

Open **Integrations** to create and manage ACME providers.

Supported provider labels are:

- Generic;
- Let's Encrypt;
- ZeroSSL;
- Buypass;
- Google Trust Services;
- Sectigo;
- Custom.

The actual service behavior comes from the directory URL and account settings.

### Provider fields

| Field | Meaning |
|---|---|
| Name | Friendly provider name |
| Provider type | Provider label |
| Directory URL | ACME v2 directory endpoint |
| Account email | Contact address |
| EAB key ID and HMAC key | External Account Binding values when required |
| Staging | Marks a test provider |
| Enabled | Allows new requests to use it |
| Notes | Optional operator notes |
| Organization / Department | Enterprise enrollment details |
| Certificate profile / Product type | Provider-specific certificate selection |
| Allowed domain pattern | Optional provider-side domain rule |

Start with a staging service. It avoids production rate limits while you test DNS and Vault access.

### ACME account actions

CertDiscovery supports a persistent account lifecycle:

- **Test directory** checks that the ACME directory can be reached.
- **Register account** creates and stores a reusable account.
- **Test account** confirms that the stored account still works.
- **Disable account** stops new use of that account.
- **Rotate account key** changes the account key while keeping account history.

The ACME account key and EAB secret are protected. Events such as registration, use, disable, and rotation are recorded.

### Sectigo

Sectigo commonly needs EAB plus organization, department, profile, or product values. See [Sectigo ACME integration](../integrations/sectigo-acme.md) for provider-specific setup.

---

## 13. DNS providers

CertDiscovery uses DNS-01 challenges for certificate requests.

### Provider types

| Type | Use |
|---|---|
| Cloudflare | API token with zone read and DNS edit rights |
| Route53 | AWS hosted zone with an AWS identity |
| Azure DNS | Azure DNS zone with an Azure identity |
| Generic | Manual DNS workflow; CertDiscovery shows the TXT name and value |

### Common fields

- provider name;
- zone name;
- enabled state;
- notes;
- TXT TTL;
- propagation timeout;
- propagation polling interval.

### Cloudflare

Store an API token with only the needed zone permissions. CertDiscovery preserves unrelated TXT values. During cleanup, it removes only the TXT value that belongs to the current challenge.

### AWS Route53 authentication

Available modes are:

- Default Credential Chain;
- Assume Role;
- Workload Identity;
- Static Credentials.

Depending on the mode, configure the hosted zone ID, region, role ARN, access key, secret key, or session token. Prefer workload identity or a default runtime role over long-lived static keys.

### Azure DNS authentication

Available modes are:

- Default Azure Credential;
- Managed Identity;
- Workload Identity;
- Service Principal.

Depending on the mode, enter the tenant, subscription, resource group, client ID, managed identity client ID, or client secret.

### Test a DNS provider

Use **Test DNS** before requesting a certificate. The test checks:

1. credentials;
2. zone access;
3. TXT publication;
4. authoritative DNS propagation;
5. cleanup.

If the test fails, the integration page shows the latest health-check status and error.

More setup details are in [Enterprise DNS integration](../integrations/enterprise-dns.md).

---

## 14. Certificate requests, issuance, and renewal

### Create a request

Open **Certificate Requests**, select **New request**, and enter:

| Field | Meaning |
|---|---|
| Request type | Standard or Wildcard |
| Domain | Primary DNS name |
| Subject Alternative Names | Other DNS names, separated as shown in the form |
| ACME provider | Enabled provider and active account |
| DNS provider | Automatic provider or manual DNS |
| Vault server | Destination for the managed bundle |
| Vault secret path | Versioned KV v2 path |
| Schedule check | Enables automatic renewal checks |
| Renewal threshold | Renew when the remaining validity reaches this many days |
| CRON expression | Renewal check schedule |

For a wildcard request, use a wildcard name such as `*.example.com`. DNS-01 is required.

### Manual lifecycle

The request states are:

```text
Draft
  -> PendingDns
  -> ReadyToValidate
  -> Validating
  -> Issued
  -> StoredInVault
```

An operation can move the request to `Failed`. The detail page shows the error.

The practical workflow is:

1. **Start challenge** creates the ACME order and DNS-01 values.
2. **Publish DNS** publishes TXT records when an automatic provider is selected.
3. For manual DNS, copy the shown name and value to your DNS system.
4. Wait for authoritative DNS propagation.
5. **Validate, issue, and store** asks the ACME service to validate, creates the certificate, adds public metadata to inventory, and stores the managed bundle in Vault.
6. **Cleanup DNS** removes the exact challenge TXT value when needed.

The detail page shows:

- all requested domains;
- current state;
- ACME provider and account;
- DNS TXT name and value;
- DNS publication status;
- ACME order location;
- certificate ID;
- Vault path;
- issue and store times;
- schedule information;
- renewal links;
- last error.

### Automatic renewal

The built-in renewal worker checks due requests regularly. For each due request it:

1. checks the current certificate validity;
2. schedules the next check if renewal is not needed;
3. creates a fresh challenge when the threshold is reached;
4. publishes automatic DNS records;
5. waits for propagation;
6. validates and issues;
7. writes a new Vault KV version;
8. cleans up the DNS value;
9. links the new request to the previous request.

Manual DNS requests stop and wait for a person to publish the TXT record.

You can use **Run schedule check** on a request detail page to test its scheduling logic immediately.

### Edit and delete

A request can be edited when its lifecycle state allows it. Be careful when changing provider or Vault information after work has started. Deleting a request removes lifecycle metadata; it does not automatically remove certificate versions from Vault or uninstall deployed certificates.

---

## 15. Certificate deployments

Certificate issuance and deployment are separate. If deployment fails, a successfully issued request stays `StoredInVault`.

### Deployment requirements

Before creating a deployment, you need:

- a certificate request in `StoredInVault`;
- an enabled target;
- an enabled policy;
- working access from CertDiscovery or its deployment agent to the target.

### Create a target

Open **Deployments**, select **New target**, choose the type, then select **Apply target template**. The template gives you safe field names and example values.

The target has:

- a friendly name;
- a target type;
- an optional linked asset;
- configuration JSON;
- an optional protected secret;
- an enabled state;
- for IIS, a selected deployment agent.

The `Secret` field is for a credential, token, external ID, PFX password, or client secret as described by that adapter. Do not paste the certificate or private key into target JSON.

### Implemented target adapters

| Target | What it does |
|---|---|
| Fake (Test Only) | Tests success and failure paths without changing a real system |
| Microsoft IIS | Uses the Windows agent for IIS binding or Central Certificate Store work |
| NGNIX | Uses SSH, atomic file changes, fixed `nginx -t`, allow-listed reload, and TLS verification |
| Apache Web Server | Uses SSH, atomic file changes, fixed config test, allow-listed reload, and TLS verification |
| Vault KV | Writes a versioned KV secret, checks fingerprint, and can return to an earlier version |
| File System Export | Atomically writes PEM, chain, key, and optional PFX files with backup and rollback |
| Kubernetes | Creates or updates a `kubernetes.io/tls` Secret while preserving important metadata |
| AWS ACM | Imports or updates a certificate through ACM |
| Azure Key Vault | Imports a PFX or PEM as a new certificate version |
| Azure Application Gateway | Uses a versionless Key Vault secret reference or uploads a PFX from source Vault |

The data model also lists **HA Proxy**, **Traefik**, **Azure App Service**, and **AWS Load Balancer**, but there is no complete production deployer for these types in the current version. Do not use them as real production targets.

### NGNIX and Apache over SSH

The JSON template includes:

- host, SSH port, and user;
- Vault URL and path for the SSH private key;
- pinned SSH host-key fingerprint;
- certificate, private-key, full-chain, and chain paths;
- file owner, group, and modes;
- service name;
- backup retention;
- optional external verification endpoints.

The target secret stores the Vault token used to read the SSH key. The private key itself stays in Vault. Commands are fixed and allow-listed; the target cannot run arbitrary shell commands.

Always pin the SSH host key. Give the deployment user only the file and service permissions it needs.

### Vault KV target

Configure the Vault base URL, secret path, and optional namespace. Store the target Vault token in the protected Secret field.

The adapter creates a new KV version, verifies its fingerprint, keeps the previous version reference, and can roll back.

### File System Export target

Configure:

- output directory;
- certificate file;
- private-key file;
- full-chain file;
- optional PFX file;
- private and public Unix file modes;
- backup retention count.

If a PFX file is enabled, the target Secret is used as its password. Writes are atomic, and backups support rollback. Make sure the web service identity can access the directory.

### Kubernetes target

Configure:

- API server;
- namespace;
- Secret name;
- whether the Secret can be created;
- optional CA bundle field;
- annotations;
- optional workload restart list.

The target Secret field contains the Kubernetes bearer token. Use minimum, namespace-scoped RBAC. The adapter manages a `kubernetes.io/tls` Secret and protects update behavior such as metadata and resource version.

### AWS ACM target

Configure the region and authentication mode:

- Default Credential Chain;
- Assume Role;
- Workload Identity.

Static AWS access keys are not accepted by this deployment adapter. For Assume Role, the protected Secret can contain the optional External ID.

You can give an existing certificate ARN for update or allow creation. The adapter can require an earlier Vault version before it updates an existing certificate, which makes rollback safer.

### Azure Key Vault target

Configure:

- vault URI;
- certificate name;
- authentication mode;
- tenant and client values when needed;
- import format: PFX or PEM;
- content type;
- enabled state and tags;
- rollback version requirement.

Authentication can use Default Azure Credential, Managed Identity, Workload Identity, or Service Principal. Only Service Principal needs the protected client secret in the target Secret field.

If an Azure Application Gateway target depends on a Key Vault certificate target, CertDiscovery protects changes that would break that dependency.

### Azure Application Gateway target

Configure the subscription, resource group, gateway, listener, SSL certificate name, and authentication.

Two modes are available:

- `KeyVaultReference` points the listener certificate to a **versionless** Key Vault secret URI such as `https://vault.vault.azure.net/secrets/example-com`. The gateway needs a suitable user-assigned identity and access.
- `DirectUpload` reads PFX data from the source Vault and uploads it to the gateway.

You can configure a provisioning timeout, rollback requirements, and external verification endpoints.

### Create a deployment policy

Policy fields control:

| Field | Meaning |
|---|---|
| Require approval | Deployment waits for an Admin |
| Automatic deployment | Allows automated lifecycle use |
| Max attempts | Maximum work attempts |
| Retry delay | Wait before retry |
| Rollback on failure | Try to restore the previous state |
| Verification timeout | Timeout for endpoint verification |
| Deployment window | Optional allowed time window |
| Enabled | Makes the policy selectable |
| Quorum mode | All, Any, or Percentage |
| Quorum percentage | Required percentage in Percentage mode |
| Minimum successful nodes | Absolute minimum successes |
| Verification attempts | Number of verification rounds |
| Verification interval | Delay between rounds |
| Rollback on partial verification | Roll back when nodes show mixed results |

Quorum behavior:

- `All`: every endpoint must present the expected certificate.
- `Any`: one successful endpoint is enough.
- `Percentage`: the required percentage and minimum-success value must both be met.

### Start and control a deployment

Select **Deploy certificate**, then choose:

1. a certificate stored in Vault;
2. a target;
3. a policy.

The possible actions depend on state:

- **Approve** starts an approval-required deployment.
- **Reject** ends it without deployment.
- **Retry** creates another attempt after a failure.
- **Cancel** stops pending work where allowed.
- **Rollback** asks the adapter to restore its backup.
- **Test target** checks target configuration and access without a full certificate rollout.

### Deployment state flow

```text
Pending
  -> AwaitingApproval
  -> Prechecking
  -> BackingUp
  -> Deploying
  -> Activating
  -> Verifying
  -> Succeeded
```

Other final or recovery states include:

```text
PartiallyVerified
Failed
RollingBack -> RolledBack | RollbackFailed
Cancelled
Rejected
```

### Verification

Verification can check internal target state and external TLS endpoints. For each endpoint, CertDiscovery can record:

- observed address;
- observed fingerprint;
- fingerprint match;
- SAN match;
- validity time;
- chain result;
- duration;
- error code and message.

Endpoint outcomes are `Verified`, `FingerprintMismatch`, `SanMismatch`, `Expired`, `NotYetValid`, `ChainInvalid`, or `Unreachable`.

Mixed old and new fingerprints normally produce `PartiallyVerified`. This often happens while a load balancer or cluster is still updating.

### Audit, retry, and job safety

Every important state change becomes a deployment audit event with the actor, time, status, message, and stage duration.

Background deployment jobs use:

- an idempotency key;
- claim owner and lease expiration;
- retry count and next-attempt time;
- dead-letter state.

If a worker stops, another worker can recover an expired lease. Idempotency reduces the chance of repeating the same external change.

For deeper details, see [Certificate deployment architecture](../architecture/certificate-deployment-architecture.md).

---

## 16. Microsoft IIS deployment agent

The Windows IIS agent is a separate Windows-only solution:

```text
agents/winDeployAgent/winDeployAgent.sln
```

It runs as a Windows Service and makes outbound connections to CertDiscovery. Central does not need to open an inbound management port on the IIS server.

### Build and publish

```powershell
cd agents\winDeployAgent
dotnet build .\winDeployAgent.sln
dotnet publish .\src\WinDeployAgent.Service\WinDeployAgent.Service.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

The repository also contains a WiX installer project.

### Recommended registration exchange

1. Install the agent on the IIS machine.
2. Configure `Agent:CentralUrl` and the agent name.
3. Start the Windows Service.
4. The agent creates a pending exchange and shows an approval code and Central verification URL.
5. Open **Deployment Agents** in CertDiscovery.
6. Compare the machine name, approval code, and public-key fingerprint.
7. Approve or reject the exchange.
8. The agent receives its long-term identity and begins heartbeat and job polling.

Exchange creation and polling are rate-limited. Pending exchanges expire.

An Admin can also create a short-lived one-time registration token for unattended provisioning. Prefer the approval exchange for normal interactive installation.

### Agent identity and security

The agent protects its pending registration data, long-term token, and private key with Windows DPAPI machine scope. It:

- claims only jobs assigned to its own agent ID;
- renews its job lease during long work;
- downloads a short-lived encrypted bundle;
- decrypts certificate material in memory;
- does not write a temporary PFX in binding mode;
- reports each stage and final result;
- does not execute arbitrary PowerShell.

The Windows Service identity must have the needed certificate store and IIS configuration permissions.

### IIS Binding mode

The agent:

1. imports the certificate into the configured `LocalMachine` store;
2. finds the exact site and HTTPS binding;
3. remembers the old binding and flags;
4. updates the certificate hash;
5. optionally restarts the application pool;
6. verifies the bound certificate locally;
7. restores the old binding and removes newly added certificate material if rollback is needed.

Example target JSON:

```json
{
  "siteName": "Default Web Site",
  "bindingProtocol": "https",
  "bindingIpAddress": "*",
  "bindingPort": 443,
  "bindingHost": "www.example.com",
  "sniEnabled": true,
  "certificateStoreName": "My",
  "certificateStoreLocation": "LocalMachine",
  "deploymentMode": "Binding",
  "applicationPool": "DefaultAppPool",
  "restartApplicationPool": false
}
```

Select the registered agent in the IIS target form. Only suitable agents can be selected; an online or busy state may be shown with the machine name.

### Central Certificate Store mode

The target template also contains Central Certificate Store fields such as the CCS path and PFX file name. Check the current agent version and test this mode carefully before production use. Binding mode is the main fully tested path described by the agent project.

### Agent states

An agent can be:

- Pending Registration;
- Online;
- Busy;
- Stale;
- Offline;
- Disabled;
- Revoked;
- Upgrade Required.

An Admin can inspect pending exchanges, approve or reject registration, monitor heartbeat and job data, disable an agent, or revoke it. Revocation should be treated as permanent loss of trust for that identity.

---

## 17. Users, workers, and application settings

### Users

From **Users**, an Admin can:

- view application users;
- create a user;
- choose Admin or Read access;
- enable or disable access as supported by the form.

Each person should have a separate account. Do not share the initial Admin account.

### User profile

The profile page lets the signed-in user update profile information and change the password. Use a strong, unique password.

### Workers

The worker page shows registered heartbeat identities, version, processed job count, last error, last seen time, and calculated status.

Use a unique worker name for each process. A repeated name makes operations difficult to understand.

### Worker nodes

The Admin worker-node screens let you create, edit, and manage known worker node records. These records help describe worker capacity and administration. Runtime worker authentication still uses the central worker API key.

### Application Settings

An Admin can change:

| Setting | Purpose |
|---|---|
| Scheduler enabled | Turns scheduled asset and lifecycle checks on or off |
| Default scan interval | Default minutes for asset scans |
| Critical days | Critical expiration threshold |
| Warning days | Warning threshold |
| Attention days | Early attention threshold |
| Max concurrent scans | Central scan workload limit |

Use ordered thresholds:

```text
Critical < Warning < Attention
```

For example: 7, 30, and 60 days.

---

## 18. REST API

Swagger at `/swagger` is the easiest way to see current request and response models in Development.

API JSON enums are written as names, not only as numbers.

### Authentication

- Normal API endpoints use the signed-in application cookie and role rules.
- Worker endpoints use `X-Worker-Api-Key`.
- Deployment-agent endpoints use registration or agent credentials, depending on the action.

### Asset API

```text
GET    /api/assets
GET    /api/assets/{id}
POST   /api/assets
PUT    /api/assets/{id}
DELETE /api/assets/{id}
POST   /api/assets/{id}/scan
```

`GET /api/assets` accepts filters for environment, protocol, asset type, owner, enabled state, and expiration days. Write actions require Admin.

### Certificate API

```text
GET /api/certificates
GET /api/certificates/{id}
GET /api/certificates/{id}/assets
```

These endpoints return inventory details and asset usage.

### Scan job API

```text
GET  /api/scan-jobs
GET  /api/scan-jobs/{id}
POST /api/scan-jobs
POST /api/scan-jobs/{id}/claim
POST /api/scan-jobs/{id}/complete
POST /api/scan-jobs/{id}/fail
POST /api/scan-jobs/{id}/requeue
```

The Admin API can create, claim, complete, fail, and requeue jobs. Normal Python workers usually use the worker-specific endpoints below.

### Worker API

```text
GET  /api/workers/jobs/next?workerName=...
POST /api/workers/heartbeat
POST /api/workers/scan-results
```

Every request must carry the configured worker key.

### Network Discovery API

The network discovery API supports:

- listing and creating discovery jobs;
- getting the next range-worker job;
- sending endpoint results;
- completing or failing a discovery job;
- promoting reviewed endpoints through the application action.

Worker operations are protected with the worker API-key filter. User create operations require Admin.

### Deployment agent API

The agent API supports:

- Admin creation of one-time registration tokens;
- agent registration;
- creating and polling approval exchanges;
- Admin listing and approval/rejection of exchanges;
- heartbeat;
- job claim and lease renewal;
- encrypted bundle download;
- stage result and completion reporting;
- Admin agent management.

Do not call agent job endpoints by hand unless you are developing or diagnosing the agent protocol. Lease tokens and encrypted bundles are short-lived security values.

### Errors and limits

Unhandled server errors use a problem-details response. In production, internal exception details are hidden. Registration exchange endpoints can return HTTP `429` when rate limits are exceeded.

---

## 19. Monitoring, health, and metrics

### Health endpoints

| Endpoint | Meaning |
|---|---|
| `/health` | General health |
| `/health/live` | Process is alive |
| `/health/ready` | Application is ready for traffic |

Use readiness in a container orchestrator or load balancer.

### Prometheus

`/metrics` returns Prometheus text format. Inventory metrics include certificate expiration timestamps, days to expiry, expired state, chain counts, and status totals.

Deployment metrics include:

- success and failure;
- retry;
- rollback;
- verification result;
- deployment-stage duration.

Sensitive high-cardinality values such as domain, endpoint, target name, fingerprint, or certificate content should not appear as metric labels.

### OpenTelemetry

ASP.NET Core, HTTP client, and runtime telemetry are enabled. Set an OTLP endpoint to export traces and metrics:

```text
CertificateDiscovery__OpenTelemetry__ServiceName=certificate-discovery
CertificateDiscovery__OpenTelemetry__OtlpEndpoint=http://otel-collector:4317
```

When the OTLP endpoint is empty, no external OTLP export is made.

### Logs

The web app logs to console and debug output. Docker users can read logs with:

```powershell
docker compose logs -f certificate-web
```

Do not log worker keys, Vault tokens, DNS credentials, private keys, PFX passwords, agent tokens, or decrypted bundles.

---

## 20. Architecture explained in simple language

CertDiscovery uses a layered architecture.

```text
Browser / API client
        |
ASP.NET Core Web
  UI + Controllers + Authentication
        |
Application rules and service boundaries
        |
Infrastructure adapters
  SQLite, ACME, DNS, Vault, SSH, Kubernetes, AWS, Azure
        |
External systems

Python scan workers <---- worker API ----> ASP.NET Core Web
Windows IIS agent   <---- agent API  ----> ASP.NET Core Web
```

### Projects

| Project | Responsibility |
|---|---|
| `CertificateDiscovery.Domain` | Entities, enums, and core business rules |
| `CertificateDiscovery.Application` | Interfaces, state machines, and use-case contracts |
| `CertificateDiscovery.Infrastructure` | EF Core, services, integrations, schedulers, and deployment adapters |
| `CertificateDiscovery.Contracts` | Request and response records shared by API and services |
| `CertificateDiscovery.Web` | MVC UI, API controllers, authentication, health, metrics, and startup |
| Python worker | TLS endpoint and CIDR scanning |
| Windows agent | Local IIS certificate installation |

### Discovery flow

```text
Scheduler or Admin
  -> Scan job
  -> Python worker claims job
  -> Worker connects to asset
  -> Worker sends certificate result
  -> Inventory writer parses and de-duplicates
  -> Certificate is linked to the asset
  -> Dashboard and metrics are updated
```

### ACME flow

```text
Certificate request
  -> Persistent ACME account
  -> ACME order
  -> DNS-01 challenge
  -> TXT publish and propagation check
  -> ACME validation
  -> Certificate issuance
  -> Public metadata in inventory
  -> Private managed bundle in Vault KV v2
```

Key application boundaries keep integrations separate:

- `IAcmeCertificateClient` handles ACME order and issuance behavior.
- `IDnsChallengeProvider` handles provider-specific TXT records.
- `IDnsPropagationChecker` checks authoritative DNS.
- `ICertificateStore` handles managed certificate storage.
- `ICertificateInventoryWriter` owns certificate parsing and inventory updates.
- `ICertificateRequestStateMachine` checks valid lifecycle state changes.

### Deployment flow

```text
Stored certificate in Vault
  -> Deployment record
  -> Lease-based background job
  -> Target adapter
  -> Validate
  -> Precheck
  -> Backup
  -> Deploy
  -> Activate
  -> Verify
  -> Success or rollback
```

The deployment orchestrator does not need target-specific commands. It selects an `ICertificateDeployer` adapter for the target type. This makes each integration easier to test and keeps failure and rollback rules consistent.

### Persistence

EF Core stores operational data in SQLite in the current version. Migrations define the schema. Important groups include:

- users and settings;
- assets, jobs, results, certificates, SANs, chains, and usage links;
- workers and discovery jobs;
- Vault, ACME, DNS, secret, and account records;
- certificate requests and renewal links;
- targets, policies, deployments, jobs, verification runs, and audit events;
- deployment agents, registration exchanges, and agent jobs.

---

## 21. Data, secrets, and security

### Source of truth

The database is the source of truth for inventory and workflow metadata. Vault is the source of truth for managed certificate material that includes private keys.

CertDiscovery should not store a managed PEM/PFX/private key bundle in normal database columns. Deployment reads the selected version from Vault when it needs the bundle.

### Protected secrets

Sensitive integration and target values are stored through the secret-provider boundary and protected with ASP.NET Core Data Protection. Examples include:

- Vault tokens;
- ACME account keys and EAB HMAC keys;
- DNS API tokens and client secrets;
- target tokens and credentials;
- IIS agent identity secrets.

Persist the Data Protection key ring. If you lose it, protected database secrets may become unreadable.

### Network security

CertDiscovery and its workers make outbound connections to user-defined hosts and ports. This creates SSRF and network-scanning risk.

In production:

- allow only approved destination networks;
- separate worker networks when possible;
- restrict egress with firewall rules;
- use DNS and IP controls;
- do not let untrusted users create assets or CIDR jobs;
- scan only networks where you have permission.

### Minimum permissions

- Use namespace-scoped Kubernetes RBAC.
- Prefer AWS workload roles or AssumeRole.
- Prefer Azure managed or workload identity.
- Give Vault tokens access only to required paths.
- Pin SSH host keys and restrict sudo rules.
- Give the IIS service account only the needed store and IIS rights.
- Keep worker and agent credentials separate.

### Production checklist

- Change all example passwords, tokens, and API keys.
- Use HTTPS for the web application and agent Central URL.
- Configure secure cookie behavior at the TLS edge.
- Use a persistent, protected Data Protection key location.
- Use a production Vault cluster, not dev mode.
- Rotate secrets and agent identities.
- Keep the database, key ring, and Vault backups together.
- Protect `/metrics`, Swagger, and administrative routes at the network edge.
- Review logs and Vault audit events.
- Test restore and rollback procedures.

---

## 22. Backup, upgrade, and daily operations

### What to back up

Back up these items as one recovery set:

- SQLite database;
- ASP.NET Core Data Protection keys;
- Vault data and version history;
- production configuration outside source control;
- external identity and policy configuration;
- IIS agent installer version and operational records.

The SQLite database without the Data Protection keys may contain secret references that cannot be decrypted.

### Upgrade process

1. Read release and migration notes.
2. Pause high-risk lifecycle work or use a maintenance window.
3. Back up the database, Data Protection keys, and Vault.
4. Build or pull the new images.
5. Start the web application.
6. Check migration logs.
7. Check `/health/ready`.
8. Confirm that workers and agents reconnect.
9. Run one safe asset scan.
10. Test integrations and a non-production deployment target.

In production, decide carefully whether database migrations should run automatically. You can set:

```text
CertificateDiscovery__ApplyMigrationsOnStartup=false
```

and manage migrations as a separate controlled step.

### Daily checks

- Review expired, critical, and warning certificates.
- Check failed and partially completed scans.
- Check stale and offline workers.
- Review failed and partially verified deployments.
- Check rollback and rollback-failed events.
- Review stale, offline, revoked, or upgrade-required IIS agents.
- Check Vault and DNS integration health.
- Review scheduled request errors.

### Regular checks

- Test backups and restore.
- Rotate worker, Vault, cloud, and agent credentials.
- Review user roles.
- Review unused assets and targets.
- Confirm that production endpoints still match the inventory.
- Remove old Vault versions only according to your rollback and retention policy.

---

## 23. Troubleshooting

| Problem | What to check |
|---|---|
| Web UI does not open | `docker compose ps`, web logs, port `8080`, readiness endpoint |
| Login does not work | Correct user name, changed password, account role/state, cookie and HTTPS proxy settings |
| Database startup fails | SQLite path, volume permissions, migration log, free disk space |
| Protected secret cannot be read | Data Protection key ring path, restored keys, service identity permissions |
| Worker is offline | API URL, worker key, worker name, network access, heartbeat logs |
| Worker gets no job | Scheduler, enabled assets, next scan time, pending jobs, worker polling |
| Asset scan times out | DNS, firewall, route, port, timeout, target service |
| TLS handshake fails | Protocol selection, SNI host, TLS version/cipher support, certificate server behavior |
| Scan is partially completed | Open job details and check each asset result |
| Network Discovery finds nothing | CIDR, ports, firewall, range worker, timeout, SNI limitation |
| Wrong certificate found by IP | Set the correct host/SNI and promote with reviewed values |
| Vault connection fails | URL, TLS trust, token, namespace, policy, mount path |
| Vault KV path fails | KV version, mount name, friendly path to `/data/` conversion, token policy |
| ACME directory test fails | Directory URL, proxy, DNS, TLS trust |
| ACME account fails | Account status, stored key, EAB values, provider policy |
| DNS test fails | Zone, hosted zone ID, identity, token permission, propagation timeout |
| Challenge stays pending | Exact TXT name/value, authoritative name servers, split DNS, TTL, propagation |
| Certificate is not available for deployment | Request must be `StoredInVault` and its Vault reference must work |
| Target test fails | JSON fields, enabled target, secret, network path, target permissions |
| SSH precheck fails | Vault SSH-key path, Vault token, pinned host fingerprint, user/sudo, file access |
| Kubernetes update fails | API URL, token, namespace RBAC, Secret name, resource version conflict |
| AWS ACM fails | Region, runtime identity, AssumeRole trust, ACM permission, ARN |
| Azure target fails | Tenant/subscription/resource group, identity, role assignment, Key Vault access |
| Verification is mixed | DNS or load-balancer spread, node rollout, SNI, endpoint list, quorum settings |
| Automatic rollback starts | Deployment error, activation result, verification outcome, policy settings |
| IIS agent waits at first start | Approve the pending exchange and compare the code and fingerprint |
| IIS agent is offline | Central URL, TLS trust, outbound firewall, Windows Service, DPAPI machine identity |
| IIS deployment fails | Selected agent, site/binding match, LocalMachine store permission, IIS rights |
| Agent registration gets HTTP 429 | Wait for the fixed rate-limit window and stop repeated registration loops |
| Metrics are empty | `/metrics` access, inventory data, recent activity, web logs |
| Swagger is missing | It is enabled only in Development by default |

When you investigate a deployment, start with the audit timeline. It tells you which stage failed. Then check the target adapter or agent log for that time.

---

## 24. Known limits

The current version has these important limits:

- STARTTLS negotiation is not implemented. The supported mail protocols are direct TLS variants.
- Certificate chain information depends on what the worker runtime can read from the peer.
- Network Discovery is IPv4 only and limited to `/16` through `/32`.
- SNI can be unknown during IP-based range discovery.
- Worker health uses heartbeat data, not a worker-side HTTP health endpoint.
- Private-network egress allow-listing is an operational responsibility and is not a complete built-in control.
- SQLite is the current database backend.
- HA Proxy, Traefik, Azure App Service, and AWS Load Balancer appear in the target model but do not have complete production deployment adapters.
- Some integration tests need real external systems.
- Full IIS integration tests need a Windows machine with IIS management components.
- Notification delivery to email, Teams, or Slack is not part of the current implementation.

Do not treat a visible enum or form option as proof that a production adapter is complete. Use the implemented-target table in this guide and test every target safely.

---

## 25. Glossary

| Term | Simple meaning |
|---|---|
| ACME | Protocol for automatic certificate issuance and renewal |
| Asset | Known network endpoint managed in inventory |
| Certificate chain | Leaf certificate plus issuer certificates |
| CIDR | A way to write an IP network range, such as `10.0.0.0/24` |
| DNS-01 | ACME validation made with a DNS TXT record |
| EAB | External Account Binding used by some ACME providers |
| Fingerprint | Hash that identifies one exact certificate |
| Idempotency | Protection against applying the same operation twice |
| KV v2 | Versioned HashiCorp Vault key/value secret engine |
| Lease | Time-limited ownership of a background job |
| PEM | Text format for certificates and keys |
| PFX / PKCS#12 | Binary package that can include a certificate, chain, and private key |
| Quorum | Rule that says how many verification endpoints must succeed |
| Rollback | Restore the state from before deployment |
| SAN | Extra name or address covered by a certificate |
| SNI | Host name sent during the TLS handshake |
| SSRF | Risk where a server is made to connect to an unsafe destination |
| TLS | Protocol that protects network connections |
| Vault | External secret system used for managed certificate bundles |

---

## More technical documents

- [Enterprise DNS integration](../integrations/enterprise-dns.md)
- [Sectigo ACME integration](../integrations/sectigo-acme.md)
- [Certificate deployment architecture](../architecture/certificate-deployment-architecture.md)
- [Current ACME flow](../architecture/current-acme-flow.md)
- [Current data model](../architecture/current-data-model.md)
- [Security secret inventory](../security/secret-inventory.md)
