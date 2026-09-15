// Copyright 2026 The OpenChoreo Authors
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openchoreo/community-modules/observability-logs-opensearch/internal/api/gen"
	osearch "github.com/openchoreo/community-modules/observability-logs-opensearch/internal/opensearch"
)

var (
	auditStart = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	auditEnd   = time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
)

// auditServer stands in for OpenSearch, recording the search body and path it was sent
// and returning the given payload.
type auditServer struct {
	*httptest.Server
	searchBody map[string]interface{}
	searchPath string
}

func newAuditServer(t *testing.T, payload map[string]interface{}) *auditServer {
	t.Helper()
	srv := &auditServer{}
	srv.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		srv.searchPath = r.URL.Path

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		var parsed map[string]interface{}
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Errorf("parse request body: %v", err)
		}
		srv.searchBody = parsed

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(payload)
	}))
	return srv
}

// auditSearchPayload builds a search response carrying the given hits.
func auditSearchPayload(hits []map[string]interface{}, total int) map[string]interface{} {
	return map[string]interface{}{
		"took":      3,
		"timed_out": false,
		"hits": map[string]interface{}{
			"total": map[string]interface{}{"value": total, "relation": "eq"},
			"hits":  hits,
		},
	}
}

// auditHit builds one stored audit document.
func auditHit(id, eventTime string) map[string]interface{} {
	return map[string]interface{}{
		"_id":    id,
		"_score": 1.0,
		"_source": map[string]interface{}{
			"schema_version": "1.0",
			"event_id":       id,
			"event_time":     eventTime,
			"actor": map[string]interface{}{
				"type": "user",
				"id":   "user-1",
			},
			"action":   "create_project",
			"category": "management",
			"result":   "success",
			"producer": "openchoreo-api",
			"kubernetes": map[string]interface{}{
				"namespace_name": "openchoreo-control-plane",
				"pod_name":       "openchoreo-api-abc",
				"container_name": "api-server",
			},
			"openchoreo_cluster_instance": "singleCluster",
			"log":                         `{"msg":"AUDIT-LOG"}`,
		},
	}
}

func auditHandler(t *testing.T, serverURL string) *LogsHandler {
	t.Helper()
	return NewLogsHandler(
		newTestOSClient(t, serverURL),
		nil, nil,
		osearch.NewQueryBuilder("audit-logs-"),
		nil,
		testLogger(),
	)
}

func auditRequestBody() *gen.AuditLogsQueryRequest {
	return &gen.AuditLogsQueryRequest{StartTime: auditStart, EndTime: auditEnd}
}

func TestQueryAuditLogs_NilBody(t *testing.T) {
	handler := NewLogsHandler(nil, nil, nil, nil, nil, testLogger())

	resp, err := handler.QueryAuditLogs(context.Background(), gen.QueryAuditLogsRequestObject{Body: nil})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(gen.QueryAuditLogs400JSONResponse); !ok {
		t.Fatalf("expected 400 response, got %T", resp)
	}
}

func TestQueryAuditLogs_RejectsAnInvertedWindow(t *testing.T) {
	handler := NewLogsHandler(nil, nil, nil, nil, nil, testLogger())

	resp, err := handler.QueryAuditLogs(context.Background(), gen.QueryAuditLogsRequestObject{
		Body: &gen.AuditLogsQueryRequest{StartTime: auditEnd, EndTime: auditStart},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(gen.QueryAuditLogs400JSONResponse); !ok {
		t.Fatalf("expected 400 response, got %T", resp)
	}
}

func TestQueryAuditLogs_ReturnsRecordsAndCollectorInfo(t *testing.T) {
	server := newAuditServer(t, auditSearchPayload([]map[string]interface{}{
		auditHit("evt-1", "2026-09-01T10:00:00Z"),
	}, 1))
	defer server.Close()

	resp, err := auditHandler(t, server.URL).QueryAuditLogs(
		context.Background(), gen.QueryAuditLogsRequestObject{Body: auditRequestBody()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	success, ok := resp.(gen.QueryAuditLogs200JSONResponse)
	if !ok {
		t.Fatalf("expected 200 response, got %T", resp)
	}
	if len(success.Records) != 1 {
		t.Fatalf("got %d records, want 1", len(success.Records))
	}

	record := success.Records[0]
	if record.EventId != "evt-1" || record.Actor.Id != "user-1" {
		t.Errorf("record = %+v, want evt-1 by user-1", record)
	}
	// Carried so a caller can compare it against the record's own producer claim.
	if record.Collector == nil || record.Collector.ContainerName == nil ||
		*record.Collector.ContainerName != "api-server" {
		t.Errorf("collector = %+v, want container api-server", record.Collector)
	}
}

// Emitting a zero-valued record would read as a real finding.
func TestQueryAuditLogs_SkipsMalformedDocuments(t *testing.T) {
	server := newAuditServer(t, auditSearchPayload([]map[string]interface{}{
		{"_id": "bad", "_score": 1.0, "_source": map[string]interface{}{"action": "create_project"}},
		auditHit("evt-1", "2026-09-01T10:00:00Z"),
	}, 2))
	defer server.Close()

	resp, err := auditHandler(t, server.URL).QueryAuditLogs(
		context.Background(), gen.QueryAuditLogsRequestObject{Body: auditRequestBody()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	success := resp.(gen.QueryAuditLogs200JSONResponse)
	if len(success.Records) != 1 || success.Records[0].EventId != "evt-1" {
		t.Errorf("records = %+v, want only the parseable one", success.Records)
	}
}

func TestQueryAuditLogs_TotalIsTheWindowCountNotThePageSize(t *testing.T) {
	server := newAuditServer(t, auditSearchPayload([]map[string]interface{}{
		auditHit("evt-1", "2026-09-01T10:00:00Z"),
	}, 4213))
	defer server.Close()

	resp, err := auditHandler(t, server.URL).QueryAuditLogs(
		context.Background(), gen.QueryAuditLogsRequestObject{Body: auditRequestBody()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	success := resp.(gen.QueryAuditLogs200JSONResponse)
	if success.Total != 4213 {
		t.Errorf("total = %d, want the whole-window count", success.Total)
	}
	if len(success.Records) != 1 {
		t.Errorf("records = %d, want the page that was returned", len(success.Records))
	}
}

// The contract gives no way to mark a count truncated at OpenSearch's 10000 default.
func TestQueryAuditLogs_CountsMatchesFully(t *testing.T) {
	server := newAuditServer(t, auditSearchPayload(nil, 0))
	defer server.Close()

	if _, err := auditHandler(t, server.URL).QueryAuditLogs(
		context.Background(), gen.QueryAuditLogsRequestObject{Body: auditRequestBody()}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := server.searchBody["track_total_hits"]; got != true {
		t.Errorf("track_total_hits = %v, want true so total is exact", got)
	}
}

// Audit records live in their own index, reached by wildcard rather than a day-walk.
func TestQueryAuditLogs_SearchesTheAuditWildcard(t *testing.T) {
	server := newAuditServer(t, auditSearchPayload(nil, 0))
	defer server.Close()

	if _, err := auditHandler(t, server.URL).QueryAuditLogs(
		context.Background(), gen.QueryAuditLogsRequestObject{Body: auditRequestBody()}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(server.searchPath, "audit-logs-*") {
		t.Errorf("searched %q, want the audit-logs-* pattern", server.searchPath)
	}
}

func TestQueryAuditLogs_TimelineKeepsEmptyBuckets(t *testing.T) {
	payload := auditSearchPayload(nil, 0)
	payload["aggregations"] = map[string]interface{}{
		"timeline": map[string]interface{}{
			"buckets": []map[string]interface{}{
				{
					"key_as_string": "2026-09-01T00:00:00.000Z",
					"doc_count":     0,
					"results":       map[string]interface{}{"buckets": []interface{}{}},
				},
			},
		},
	}

	server := newAuditServer(t, payload)
	defer server.Close()

	includeTimeline := true
	interval := "15m"
	body := auditRequestBody()
	body.IncludeTimeline = &includeTimeline
	body.TimelineInterval = &interval

	resp, err := auditHandler(t, server.URL).QueryAuditLogs(
		context.Background(), gen.QueryAuditLogsRequestObject{Body: body})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	success := resp.(gen.QueryAuditLogs200JSONResponse)
	if success.Timeline == nil {
		t.Fatal("timeline was requested but not returned")
	}
	if success.Timeline.Interval != "15m" {
		t.Errorf("interval = %q, want the width actually used", success.Timeline.Interval)
	}
	// A zero-count bucket is present rather than omitted, so a chart cannot be drawn
	// straight across a gap in activity.
	if len(success.Timeline.Buckets) != 1 || success.Timeline.Buckets[0].Total != 0 {
		t.Errorf("buckets = %+v, want the empty bucket kept", success.Timeline.Buckets)
	}
}

// The timeline costs an extra aggregation pass, so it is requested only when asked for.
func TestQueryAuditLogs_NoTimelineAggregationUnlessRequested(t *testing.T) {
	server := newAuditServer(t, auditSearchPayload(nil, 0))
	defer server.Close()

	if _, err := auditHandler(t, server.URL).QueryAuditLogs(
		context.Background(), gen.QueryAuditLogsRequestObject{Body: auditRequestBody()}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := server.searchBody["aggs"]; ok {
		t.Error("an unrequested timeline aggregation was sent")
	}
}

// The generated server does not enforce the contract's ceilings.
func TestQueryAuditLogs_ClampsTheLimitToTheContractMaximum(t *testing.T) {
	server := newAuditServer(t, auditSearchPayload(nil, 0))
	defer server.Close()

	limit := 50000
	body := auditRequestBody()
	body.Limit = &limit

	if _, err := auditHandler(t, server.URL).QueryAuditLogs(
		context.Background(), gen.QueryAuditLogsRequestObject{Body: body},
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := server.searchBody["size"]; got != float64(maxAuditLimit) {
		t.Errorf("size = %v, want it clamped to %d", got, maxAuditLimit)
	}
}

func TestQueryAuditLogFilterValues_ClampsMaxValuesToTheContractMaximum(t *testing.T) {
	server := newAuditServer(t, map[string]interface{}{
		"took": 1,
		"hits": map[string]interface{}{"total": map[string]interface{}{"value": 0, "relation": "eq"}},
	})
	defer server.Close()

	maxValues := 50000
	if _, err := auditHandler(t, server.URL).QueryAuditLogFilterValues(
		context.Background(), gen.QueryAuditLogFilterValuesRequestObject{
			Body: &gen.AuditLogFilterValuesRequest{
				Filter:    "actor.id",
				Query:     *auditRequestBody(),
				MaxValues: &maxValues,
			},
		}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	aggs, ok := server.searchBody["aggs"].(map[string]interface{})
	if !ok {
		t.Fatalf("search body has no aggregations: %v", server.searchBody)
	}
	terms := aggs["values"].(map[string]interface{})["terms"].(map[string]interface{})
	if got := terms["size"]; got != float64(maxAuditFilterValues) {
		t.Errorf("terms size = %v, want it clamped to %d", got, maxAuditFilterValues)
	}
}

func TestQueryAuditLogFilterValues_RejectsAnUnknownFilter(t *testing.T) {
	handler := NewLogsHandler(nil, nil, nil, nil, nil, testLogger())

	resp, err := handler.QueryAuditLogFilterValues(
		context.Background(), gen.QueryAuditLogFilterValuesRequestObject{
			Body: &gen.AuditLogFilterValuesRequest{
				Filter: "not.a.filter",
				Query:  *auditRequestBody(),
			},
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(gen.QueryAuditLogFilterValues400JSONResponse); !ok {
		t.Fatalf("expected 400 response, got %T", resp)
	}
}

func TestQueryAuditLogFilterValues_ReturnsValuesInOrder(t *testing.T) {
	payload := map[string]interface{}{
		"took":      2,
		"timed_out": false,
		"hits":      map[string]interface{}{"total": map[string]interface{}{"value": 0, "relation": "eq"}},
		"aggregations": map[string]interface{}{
			"values": map[string]interface{}{
				"buckets": []map[string]interface{}{
					{"key": "user-1", "doc_count": 10},
					{"key": "user-2", "doc_count": 4},
				},
			},
			"total_values": map[string]interface{}{
				"doc_count": 14,
				"matching":  map[string]interface{}{"value": 2},
			},
		},
	}

	server := newAuditServer(t, payload)
	defer server.Close()

	resp, err := auditHandler(t, server.URL).QueryAuditLogFilterValues(
		context.Background(), gen.QueryAuditLogFilterValuesRequestObject{
			Body: &gen.AuditLogFilterValuesRequest{
				Filter: "actor.id",
				Query:  *auditRequestBody(),
			},
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	success, ok := resp.(gen.QueryAuditLogFilterValues200JSONResponse)
	if !ok {
		t.Fatalf("expected 200 response, got %T", resp)
	}
	if success.Filter != "actor.id" {
		t.Errorf("filter = %q, want it echoed back", success.Filter)
	}
	if len(success.Values) != 2 || success.Values[0].Value != "user-1" {
		t.Errorf("values = %+v, want user-1 first", success.Values)
	}

	// Search runs with IgnoreUnavailable, so a query aimed at the wrong index answers
	// an empty aggregation rather than an error. Assert the index it actually hit.
	if !strings.Contains(server.searchPath, "audit-logs-*") {
		t.Errorf("searched %q, want the audit-logs-* pattern", server.searchPath)
	}
}

// A picker must keep offering alternatives, not just what is already selected.
func TestQueryAuditLogFilterValues_IgnoresTheNamedFiltersOwnSelections(t *testing.T) {
	server := newAuditServer(t, map[string]interface{}{
		"took":      2,
		"timed_out": false,
		"hits":      map[string]interface{}{"total": map[string]interface{}{"value": 0, "relation": "eq"}},
		"aggregations": map[string]interface{}{
			"values": map[string]interface{}{"buckets": []map[string]interface{}{}},
			"total_values": map[string]interface{}{
				"doc_count": 0,
				"matching":  map[string]interface{}{"value": 0},
			},
		},
	})
	defer server.Close()

	query := *auditRequestBody()
	query.Actor = &gen.AuditLogsActorFilter{Id: &[]string{"user-1"}}
	query.Result = &[]gen.AuditLogsQueryRequestResult{"denied"}

	if _, err := auditHandler(t, server.URL).QueryAuditLogFilterValues(
		context.Background(), gen.QueryAuditLogFilterValuesRequestObject{
			Body: &gen.AuditLogFilterValuesRequest{Filter: "actor.id", Query: query},
		}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sent, err := json.Marshal(server.searchBody)
	if err != nil {
		t.Fatalf("marshal captured body: %v", err)
	}
	if strings.Contains(string(sent), "user-1") {
		t.Error("the named filter's own selection was applied to its own value query")
	}
	// The rest of the query still narrows which records the values are drawn from.
	if !strings.Contains(string(sent), "denied") {
		t.Error("the query's other filters were dropped")
	}
}

// The contract says to ignore these rather than reject them.
func TestQueryAuditLogFilterValues_IgnoresRecordQueryControls(t *testing.T) {
	server := newAuditServer(t, map[string]interface{}{
		"took":      2,
		"timed_out": false,
		"hits":      map[string]interface{}{"total": map[string]interface{}{"value": 0, "relation": "eq"}},
		"aggregations": map[string]interface{}{
			"values": map[string]interface{}{"buckets": []map[string]interface{}{}},
			"total_values": map[string]interface{}{
				"doc_count": 0,
				"matching":  map[string]interface{}{"value": 0},
			},
		},
	})
	defer server.Close()

	limit := 7
	includeTimeline := true
	sortOrder := gen.AuditLogsQueryRequestSortOrder("asc")

	query := *auditRequestBody()
	query.Limit = &limit
	query.IncludeTimeline = &includeTimeline
	query.SortOrder = &sortOrder

	resp, err := auditHandler(t, server.URL).QueryAuditLogFilterValues(
		context.Background(), gen.QueryAuditLogFilterValuesRequestObject{
			Body: &gen.AuditLogFilterValuesRequest{Filter: "producer", Query: query},
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(gen.QueryAuditLogFilterValues200JSONResponse); !ok {
		t.Fatalf("expected 200 response, got %T", resp)
	}

	if server.searchBody["size"] != float64(0) {
		t.Errorf("size = %v, want 0; query.limit must not become the page size", server.searchBody["size"])
	}
	if _, ok := server.searchBody["sort"]; ok {
		t.Error("query.sortOrder was applied to an aggregation-only request")
	}
	if _, ok := server.searchBody["aggs"].(map[string]interface{})["timeline"]; ok {
		t.Error("query.includeTimeline was honoured on the filter values operation")
	}
}

// 501 tells a missing capability apart from a filter that genuinely has no values.
func TestQueryPlatformLogFilterValues_NotImplemented(t *testing.T) {
	handler := NewLogsHandler(nil, nil, nil, nil, nil, testLogger())

	resp, err := handler.QueryPlatformLogFilterValues(
		context.Background(), gen.QueryPlatformLogFilterValuesRequestObject{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(gen.QueryPlatformLogFilterValues501JSONResponse); !ok {
		t.Fatalf("expected 501 response, got %T", resp)
	}
}
