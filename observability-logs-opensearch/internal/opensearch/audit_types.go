// Copyright 2026 The OpenChoreo Authors
// SPDX-License-Identifier: Apache-2.0

package opensearch

import (
	"encoding/json"
	"fmt"
	"time"
)

// AuditRecord is one stored audit event, in the field names it was published with.
//
// The json tags are the record's own snake_case spelling, so a document read back out
// of OpenSearch unmarshals into this directly and a field rename upstream surfaces as
// an empty value here rather than being absorbed by a translation table.
type AuditRecord struct {
	SchemaVersion string         `json:"schema_version"`
	EventID       string         `json:"event_id"`
	EventTime     time.Time      `json:"event_time"`
	Actor         AuditActor     `json:"actor"`
	Action        string         `json:"action"`
	Category      string         `json:"category"`
	Result        string         `json:"result"`
	RequestID     string         `json:"request_id"`
	SourceIP      string         `json:"source_ip"`
	UserAgent     string         `json:"user_agent"`
	Producer      string         `json:"producer"`
	Surface       string         `json:"surface"`
	OperationID   string         `json:"operation_id"`
	HTTP          *AuditHTTPInfo `json:"http"`
	Resource      *AuditResource `json:"resource"`
	Metadata      map[string]any `json:"metadata"`

	// Log is the raw line the collector ingested, retained alongside the parsed
	// fields by the collector's Preserve_Key. It is the ground truth a parsing
	// discrepancy is settled against.
	Log string `json:"log"`

	// Kubernetes and ClusterInstance are stamped by the collector rather than by the
	// emitting service, which is what makes them worth comparing against the
	// record's own producer claim.
	Kubernetes      AuditCollectorInfo `json:"kubernetes"`
	ClusterInstance string             `json:"openchoreo_cluster_instance"`
}

// AuditActor is who performed the action. ID is unique only within Issuer.
type AuditActor struct {
	Type         string              `json:"type"`
	ID           string              `json:"id"`
	Issuer       string              `json:"issuer"`
	SessionID    string              `json:"session_id"`
	Entitlements map[string][]string `json:"entitlements"`
}

// AuditHTTPInfo is the request line, for an event that arrived over HTTP.
type AuditHTTPInfo struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// AuditResource is the target resource and the point in the tree the decision was
// authorized at.
type AuditResource struct {
	Type      string `json:"type"`
	Namespace string `json:"namespace"`

	// Environment is dual-scoped as {namespace}/{name}, stored exactly as
	// authorization evaluated it, unlike its bare-name siblings above and below.
	Environment string         `json:"environment"`
	Project     string         `json:"project"`
	Component   string         `json:"component"`
	Resource    string         `json:"resource"`
	UID         string         `json:"uid"`
	Name        string         `json:"name"`
	Metadata    map[string]any `json:"metadata"`
}

// AuditCollectorInfo is where the collector read the record from.
type AuditCollectorInfo struct {
	NamespaceName string `json:"namespace_name"`
	PodName       string `json:"pod_name"`
	ContainerName string `json:"container_name"`
}

// AuditFilterValue is one value a filter takes, with how many records carry it.
type AuditFilterValue struct {
	Value string
	Count int64
}

// AuditTimeline is per-interval counts across the queried window.
type AuditTimeline struct {
	Interval string
	Buckets  []AuditTimelineBucket
}

// AuditTimelineBucket is one interval of the timeline.
type AuditTimelineBucket struct {
	StartTime time.Time
	Total     int64
	Counts    map[string]int64
}

// ParseAuditRecord reads a search hit into an audit record.
//
// Returns an error rather than a zero-valued record when the document does not parse:
// an audit record with a blank actor or a zero event time reads as a real reading of
// "nobody, at the epoch", which is a worse answer than saying the document is
// unreadable.
func ParseAuditRecord(hit Hit) (AuditRecord, error) {
	raw, err := json.Marshal(hit.Source)
	if err != nil {
		return AuditRecord{}, fmt.Errorf("failed to re-encode document: %w", err)
	}

	var record AuditRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return AuditRecord{}, fmt.Errorf("failed to parse document: %w", err)
	}

	// The contract requires these on every record, and this module owns that
	// guarantee. A document missing them was not written by an audit producer.
	if record.EventID == "" {
		return AuditRecord{}, fmt.Errorf("document has no event_id")
	}
	if record.EventTime.IsZero() {
		return AuditRecord{}, fmt.Errorf("document has no event_time")
	}

	return record, nil
}
