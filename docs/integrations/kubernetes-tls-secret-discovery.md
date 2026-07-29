# Kubernetes TLS Secret discovery

CertDiscovery can import public certificate material from Kubernetes Secrets whose
type is `kubernetes.io/tls`. The integration reads Secret metadata and `tls.crt`.
It never reads, displays, logs, or stores `tls.key`.

## Configure a cluster

Open **Integrations**, select **New Kubernetes Cluster**, and configure:

- an absolute HTTPS Kubernetes API server URL;
- a service-account bearer token;
- a comma-separated namespace allowlist, or leave it empty for all namespaces.

The bearer token is stored through CertDiscovery's protected secret provider.
Changing other cluster settings does not require re-entering the token.

## Minimum RBAC

Prefer one Role and RoleBinding per scanned namespace:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: certdiscovery-tls-secret-reader
  namespace: production
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["list"]
```

Bind the Role to the service account used by CertDiscovery. Repeat it only for
namespaces that should be scanned. Scanning all namespaces requires an equivalent
ClusterRole and ClusterRoleBinding and should be used only when necessary.

## Inventory behavior

- `tls.crt` may contain a leaf certificate followed by chain certificates.
- Certificates are deduplicated by the existing SHA-256 fingerprint.
- SANs, issuer, subject, validity dates, and chain entries are imported.
- Every cluster / namespace / Secret source is preserved, including when the
  same certificate appears in multiple Secrets.
