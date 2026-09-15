{{/*
Copyright 2026 The OpenChoreo Authors
SPDX-License-Identifier: Apache-2.0
*/}}

{{/*
Render the full image reference for a module component, honoring the
global.imageRegistry override. When the override is set, it replaces the
registry host of the image repository (the first path segment containing
"." or ":" or equal to "localhost", per the container reference rules).
The override value may itself carry a path (e.g. registry.example.com/ghcr.io)
for path-preserving mirrors.

Usage: {{ include "observability-logs-opensearch.image" (dict "image" .Values.adapter.image "context" .) }}
Parameters:
  - image: The component image block (repository, tag)
  - context: The chart root context (.)
*/}}
{{- define "observability-logs-opensearch.image" -}}
{{- $repo := .image.repository -}}
{{- with .context.Values.global.imageRegistry -}}
{{- $parts := splitList "/" $repo -}}
{{- $first := first $parts -}}
{{- if and (gt (len $parts) 1) (or (contains "." $first) (contains ":" $first) (eq $first "localhost")) -}}
{{- $repo = join "/" (rest $parts) -}}
{{- end -}}
{{- $repo = printf "%s/%s" . $repo -}}
{{- end -}}
{{- printf "%s:%s" $repo (.image.tag | default .context.Chart.AppVersion) -}}
{{- end }}

{{/*
Return auditLogs.indexPrefix, failing the render unless OpenSearch accepts it as an
index name prefix. It becomes an index pattern in the collector, the mapping template
and the retention policy, so a wildcard or comma would widen all three onto other
signals' indices. 244 leaves room for the collector's -YYYY-MM-DD within 255 bytes.

Usage: {{ include "observability-logs-opensearch.auditIndexPrefix" . }}
*/}}
{{- define "observability-logs-opensearch.auditIndexPrefix" -}}
{{- $prefix := .Values.auditLogs.indexPrefix -}}
{{- if not $prefix -}}
{{- fail "auditLogs.indexPrefix must not be empty: the collector would write to indices the template, the retention policy and the adapter do not read, each falling back to audit-logs-" -}}
{{- end -}}
{{- if not (regexMatch "^[a-z0-9][a-z0-9._-]*$" $prefix) -}}
{{- fail (printf "auditLogs.indexPrefix %q must start with a lowercase letter or digit and contain only lowercase letters, digits, '.', '_' and '-'" $prefix) -}}
{{- end -}}
{{- if gt (len $prefix) 244 -}}
{{- fail (printf "auditLogs.indexPrefix must be at most 244 characters, got %d" (len $prefix)) -}}
{{- end -}}
{{- $prefix -}}
{{- end }}
