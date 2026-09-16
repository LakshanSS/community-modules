# Observability Logs Module for OpenSearch

This module collects logs using [Fluent Bit](https://fluentbit.io) and stores them in [OpenSearch](https://opensearch.org).

## Prerequisites

- [OpenChoreo](https://openchoreo.dev) must be installed with the **observability plane** enabled for this module to work.

## Installation

### Pre-requisites

1. OpenSearch setup scripts in this helm chart need admin credentials to connect to OpenSearch and configure it. OpenChoreo uses the External Secrets Operator to manage secrets. Add your OpenSearch credentials (username and password) to a secret store and use an `ExternalSecret` resource to generate a Kubernetes secret from it.
   Refer to the [secret management guide](https://openchoreo.dev/docs/platform-engineer-guide/secret-management/) for more details.

For example, the command below pulls values from the `ClusterSecretStore` created earlier in the [OpenChoreo installation guide](https://openchoreo.dev/docs).

```bash
kubectl apply -f - <<EOF
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: opensearch-admin-credentials
  namespace: openchoreo-observability-plane
spec:
  refreshInterval: 1h
  secretStoreRef:
    kind: ClusterSecretStore
    name: default
  target:
    name: opensearch-admin-credentials
  data:
  - secretKey: username
    remoteRef:
      key: opensearch-username
      property: value
  - secretKey: password
    remoteRef:
      key: opensearch-password
      property: value
EOF
```

2. If you wish to use the Kubernetes operator-based OpenSearch version included with this Helm chart, install the operator as follows

```bash
helm repo add opensearch-operator https://opensearch-project.github.io/opensearch-k8s-operator/
helm repo update
helm upgrade --install opensearch-operator opensearch-operator/opensearch-operator \
  --create-namespace \
  --namespace openchoreo-observability-plane \
  --version 2.8.0 \
  --set kubeRbacProxy.image.repository=quay.io/brancz/kube-rbac-proxy \
  --set kubeRbacProxy.image.tag=v0.15.0
```

## Deploy Helm chart

> **Note:** If you wish to use the Kubernetes operator-based OpenSearch version, add `--set openSearch.enabled=false --set openSearchCluster.enabled=true --set openSearchCluster.credentialsSecretName="opensearch-admin-credentials"` flags when installing the Helm chart. The admin password will be read from the credentials secret at install time.

```bash
helm upgrade --install observability-logs-opensearch \
  oci://ghcr.io/openchoreo/helm-charts/observability-logs-opensearch \
  --create-namespace \
  --namespace openchoreo-observability-plane \
  --version 0.5.3 \
  --set adapter.openSearchSecretName="opensearch-admin-credentials" \
  --set openSearchSetup.openSearchSecretName="opensearch-admin-credentials"
```

> **Note:** If OpenSearch is already installed by another module (e.g., `observability-tracing-opensearch`), disable it to avoid conflicts:
>
> ```bash
> helm upgrade --install observability-logs-opensearch \
>   oci://ghcr.io/openchoreo/helm-charts/observability-logs-opensearch \
>   --create-namespace \
>   --namespace openchoreo-observability-plane \
>   --version 0.5.3 \
>   --set adapter.openSearchSecretName="opensearch-admin-credentials" \
>   --set openSearch.enabled=false \
>   --set openSearchSetup.openSearchSecretName="opensearch-admin-credentials"
> ```

## Enable log collection

Every install that enables Fluent Bit must name its cluster:

```bash
--set fluentBitCustomizations.clusterInstance=clusterX
```

The value is required and the chart refuses to render without it. It cannot be
defaulted: `planeID` defaults to `default` in every plane chart, so two clusters running
defaults would produce indistinguishable records, and nothing surfaces the mistake until
the second cluster exists. The collector stamps it on each record as
`openchoreo_cluster_instance`, and platform observability filters on it.

`kube-system` is excluded from collection. CoreDNS, kube-proxy, the CNI and the API
server sit a layer below OpenChoreo; static pods cannot be labelled, and managed
providers reconcile that namespace anyway.

### Single-cluster topology

In a **single-cluster topology**, where the observability plane runs in the same cluster
as the data-plane / workflow-plane clusters, enable Fluent Bit in the already installed Helm chart
to start collecting logs from the cluster and publish them to OpenSearch:

```bash
helm upgrade observability-logs-opensearch \
  oci://ghcr.io/openchoreo/helm-charts/observability-logs-opensearch \
  --create-namespace \
  --namespace openchoreo-observability-plane \
  --version 0.5.3 \
  --reuse-values \
  --set fluent-bit.enabled=true \
  --set fluentBitCustomizations.clusterInstance=singleCluster
```

### Multi-cluster topology

In a **multi-cluster topology**, where the observability plane runs in a separate cluster
from the control-plane/ data-plane / workflow-plane clusters, you need two things:

1. **On the observability plane cluster**: expose OpenSearch through the gateway via TLS passthrough so remote fluent-bit instances can reach it.
2. **On each remote cluster**: install this chart with only fluent-bit enabled, pointed at the obs cluster's OpenSearch endpoint.

#### Observability plane cluster setup

The recommended approach is the **OpenSearch Operator** (`openSearchCluster.enabled=true`), which automatically creates the TLSRoute needed for gateway passthrough. Install the operator first (see [Prerequisites](#pre-requisites)), then install the chart with:

```bash
helm upgrade --install observability-logs-opensearch \
  oci://ghcr.io/openchoreo/helm-charts/observability-logs-opensearch \
  --create-namespace \
  --namespace openchoreo-observability-plane \
  --version 0.5.3 \
  --set adapter.openSearchSecretName="opensearch-admin-credentials" \
  --set openSearch.enabled=false \
  --set openSearchCluster.enabled=true \
  --set openSearchCluster.credentialsSecretName="opensearch-admin-credentials" \
  --set openSearchSetup.openSearchSecretName="opensearch-admin-credentials"
```

You also need TLS passthrough enabled on the observability plane gateway. When installing the `openchoreo-observability-plane` chart, include:

```yaml
gateway:
  tlsPassthrough:
    enabled: true
    hostname: "opensearch.<OBS_BASE_DOMAIN>"
```

> **Note:** If you use the helm subchart OpenSearch (`openSearch.enabled=true`) instead of the operator, the TLSRoute is not auto-generated and the `BackendConfigPolicy` on the default `opensearch` Service conflicts with TLS passthrough (causes double-TLS). You would need to create a separate passthrough Service and TLSRoute manually. The operator approach avoids this complexity.

#### Remote cluster setup (control-plane / data-plane / workflow-plane clusters)

Install the chart with only fluent-bit enabled (set the `clusterInstance` accordingly):

```bash
helm upgrade --install observability-logs-opensearch \
  oci://ghcr.io/openchoreo/helm-charts/observability-logs-opensearch \
  --create-namespace \
  --namespace openchoreo-observability-plane \
  --version 0.5.3 \
  --set adapter.enabled=false \
  --set openSearch.enabled=false \
  --set openSearchCluster.enabled=false \
  --set openSearchSetup.enabled=false \
  --set fluent-bit.enabled=true \
  --set fluentBitCustomizations.clusterInstance=clusterX \
  --set fluent-bit.openSearchHost=opensearch.<OBS_BASE_DOMAIN> \
  --set fluent-bit.openSearchPort=<gateway-tls-passthrough-port> \
  --set fluent-bit.openSearchVHost=opensearch.<OBS_BASE_DOMAIN>
```

> **Note:**
>
> - The `opensearch-admin-credentials` secret must exist on the remote cluster. If you don't have a shared secret backend, create it manually (see the [Multi-Cluster Connectivity](https://openchoreo.dev/docs/platform-engineer-guide/multi-cluster-connectivity/) guide).
> - `fluent-bit.openSearchHost` and `fluent-bit.openSearchVHost` should match the TLS passthrough hostname on the obs gateway.
> - `fluent-bit.openSearchPort` should match the passthrough listener port (commonly `11443` if the obs gateway uses non-standard ports).
> - The adapter and setup job are disabled because they only need to run on the observability plane cluster.
> - On the **control plane** cluster, add `--set auditLogs.enabled=true` to also collect the audit trail. See [Enable audit log collection](#enable-audit-log-collection).

## Enable audit log collection

OpenChoreo's audit trail — who did what, from where, and whether it was allowed — is
written by `openchoreo-api` and `observer` to their container logs. This module can route
those records to an index of their own, `audit-logs-*`, so they are kept under their own
retention rather than expiring with operational logs.

Enable it alongside Fluent Bit:

```bash
helm upgrade observability-logs-opensearch \
  oci://ghcr.io/openchoreo/helm-charts/observability-logs-opensearch \
  --create-namespace \
  --namespace openchoreo-observability-plane \
  --version 0.5.3 \
  --reuse-values \
  --set fluent-bit.enabled=true \
  --set fluentBitCustomizations.clusterInstance=singleCluster \
  --set auditLogs.enabled=true
```

Audit records are produced by the control plane and the observability plane. In a
multi-cluster topology, Fluent Bit must therefore be running — and `auditLogs.enabled`
set — in the cluster hosting `openchoreo-api` and `observer`, which is not necessarily
the cluster hosting OpenSearch. See [Multi-cluster topology](#multi-cluster-topology) for
how to point a remote Fluent Bit at the observability plane.

### Trusted producers

`auditLogs.producers` is an allowlist, and it is a security boundary rather than ordinary
configuration. **Each entry grants a workload the right to write into the audit trail.**

```yaml
auditLogs:
  producers:
    - producer: openchoreo-api
      namespace: openchoreo-control-plane
      container: api-server
    - producer: observer
      namespace: openchoreo-observability-plane
      container: observer
```

Each entry becomes one Fluent Bit rule that matches on the container log **filename**,
which the kubelet writes — not on anything in the log line. This is what makes the trail
trustworthy: a workload that prints

```json
{"level":"INFO","msg":"AUDIT-LOG","producer":"openchoreo-api","action":"delete_project","result":"success"}
```

to its stdout produces a line that looks exactly like a real audit record, and it still
lands in `container-logs-*` and never in the audit index, because its pod is not in the
allowlist. Widening the list removes that guarantee for the workload you add.

Two consequences worth knowing before you change it:

- **The defaults assume the default release namespaces.** If you install the control
  plane or the observability plane into different namespaces, edit these entries — or
  audit collection silently stops. Nothing errors; the index simply stays empty.
- The `container` values are container names, not deployment names. The API server's
  container is `api-server`, not `openchoreo-api`.

### Configuring the audit destination

| Value | Default | Purpose |
| ----- | ------- | ------- |
| `auditLogs.enabled` | `false` | Route audit records to their own index |
| `auditLogs.indexPrefix` | `audit-logs-` | Index name prefix; daily indices are `audit-logs-YYYY-MM-DD` |
| `auditLogs.producers` | the two above | The trusted-producer allowlist |

The index template and retention policy are applied on **every** install, whether or not
`auditLogs.enabled` is set. This is deliberate: an index created before its template gets
dynamic mappings and answers nothing, and applying the template afterwards does not
repair indices already written. Until audit is enabled they are metadata against an index
pattern that matches nothing.

### Retention

```bash
--set openSearchSetup.dataRetentionTime.auditLogs=365d
```

Audit defaults to **365 days**, against 30 for container logs and Kubernetes events.
Needing a different retention is the reason audit is a separate stream rather than a
filter over the container logs, so the two are not expected to match. Changing the value
and upgrading reconciles the policy onto the indices that already exist.

## Troubleshooting

### Observer returns no logs

If Fluent Bit is shipping and `container-logs-*` is filling but Observer queries come back empty, the index was likely created before `openSearchSetup` applied its template — so it has dynamic mappings that don't match what the adapter queries. Delete the index and let Fluent Bit recreate it:

```bash
kubectl exec -n openchoreo-observability-plane opensearch-master-0 \
  -- curl -ksu admin:<password> -X DELETE 'https://localhost:9200/container-logs-*'
```

Only logs written after the deletion will appear (Fluent Bit's tail cursor persists at `/var/lib/fluent-bit/db/tail-container-logs.db`). Generate fresh traffic, or remove that DB and restart the DaemonSet to backfill.

### Audit queries return nothing, but the index is filling

Same cause as above, and the same fix with the audit pattern: an `audit-logs-*` index
created before `openSearchSetup` applied its template carries dynamic mappings instead of
the declared ones, so filters match nothing.

```bash
kubectl exec -n openchoreo-observability-plane opensearch-master-0 \
  -- curl -ksu admin:<password> -X DELETE 'https://localhost:9200/audit-logs-*'
```

**Deleting an audit index destroys audit records.** Unlike container logs, they are not
regenerated by fresh traffic — only new activity is recorded. Confirm the index really is
mis-mapped before deleting it, by checking that the mapping declares the audit fields:

```bash
kubectl exec -n openchoreo-observability-plane opensearch-master-0 \
  -- curl -ksu admin:<password> 'https://localhost:9200/audit-logs-*/_mapping?pretty'
```

### No audit records are collected at all

The index stays empty and nothing errors. In order of likelihood:

1. `auditLogs.enabled` is not set in the cluster where `openchoreo-api` and `observer`
   run. In a multi-cluster install this is the control plane cluster, not the one running
   OpenSearch.
2. The control plane or observability plane is installed into a non-default namespace, so
   no `auditLogs.producers` entry matches. Compare the entries against the pods'
   **namespace** and **container** names.
3. Audit publishing is disabled on the producer itself. That is configured in the
   OpenChoreo control plane and observability plane charts, not here.

Check what the collector is doing — the audit rules appear as their own emitters:

```bash
kubectl exec -n openchoreo-observability-plane ds/fluent-bit \
  -- curl -s localhost:2020/api/v1/metrics | grep audit_emitter
```

## Dependencies

Bundled upstream Helm charts:

| Chart      | Repository                                        |
| ---------- | ------------------------------------------------- |
| opensearch | https://opensearch-project.github.io/helm-charts/ |
| fluent-bit | https://fluent.github.io/helm-charts              |

## Compatibility

> **Note:** The Helm chart versions specified in the installation commands above are for the latest module version compatible with the development version of OpenChoreo. Refer to the compatibility table below to determine the appropriate module version for your OpenChoreo installation.

| Module Version | OpenChoreo Version |
| -------------- | ------------------ |
| v0.5.x         | v1.2.x             |
| v0.4.x         | v1.1.x             |
| v0.3.x         | v1.0.x             |
