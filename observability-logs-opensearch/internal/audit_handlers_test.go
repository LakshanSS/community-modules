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

// auditServer stands in for OpenSearch. It answers the point-in-time create with a
// fixed id, records the search body it was sent, and returns the given payload.
type auditServer struct {
	*httptest.Server
	searchBody map[string]interface{}
	searchPath string
	pitPath    string
}

func newAuditServer(t *testing.T, payload map[string]interface{}) *auditServer {
	t.Helper()
	srv := &auditServer{}
	srv.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if strings.Contains(r.URL.Path, "point_in_time") {
			srv.pitPath = r.URL.Path
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"pit_id": "pit-1"})
			return
		}
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
func auditSearchPayload(hits []map[string]interface{}, total int, relation string) map[string]interface{} {
	return map[string]interface{}{
		"took":      3,
		"timed_out": false,
		"pit_id":    "pit-1",
		"hits": map[string]interface{}{
			"total": map[string]interface{}{"value": total, "relation": relation},
			"hits":  hits,
		},
	}
}

// auditHit builds one stored audit document.
func auditHit(id, eventTime string, sortValues []interface{}) map[string]interface{} {
	return map[string]interface{}{
		"_id":    id,
		"_score": 1.0,
		"sort":   sortValues,
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
		time.Minute,
		nil,
		testLogger(),
	)
}

func auditRequestBody() *gen.AuditLogsQueryRequest {
	return &gen.AuditLogsQueryRequest{StartTime: auditStart, EndTime: auditEnd}
}

func TestQueryAuditLogs_NilBody(t *testing.T) {
	handler := NewLogsHandler(nil, nil, nil, nil, 0, nil, testLogger())

	resp, err := handler.QueryAuditLogs(context.Background(), gen.QueryAuditLogsRequestObject{Body: nil})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(gen.QueryAuditLogs400JSONResponse); !ok {
		t.Fatalf("expected 400 response, got %T", resp)
	}
}

func TestQueryAuditLogs_RejectsAnInvertedWindow(t *testing.T) {
	handler := NewLogsHandler(nil, nil, nil, nil, 0, nil, testLogger())

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
		auditHit("evt-1", "2026-09-01T10:00:00Z", []interface{}{"2026-09-01T10:00:00Z", "evt-1"}),
	}, 1, "eq"))
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
	// The collected origin is carried so a caller can compare it against the
	// record's own producer claim.
	if record.Collector == nil || record.Collector.ContainerName == nil ||
		*record.Collector.ContainerName != "api-server" {
		t.Errorf("collector = %+v, want container api-server", record.Collector)
	}
	// The raw line is the ground truth a parsing discrepancy is settled against.
	if record.Log == nil || *record.Log == "" {
		t.Error("record carries no raw log line")
	}
	if success.TotalRelation != "eq" {
		t.Errorf("totalRelation = %q, want eq", success.TotalRelation)
	}
}

// A record that does not parse is skipped rather than emitted zero-valued: a blank
// actor at the epoch reads as a real finding of "nobody, at no time".
func TestQueryAuditLogs_SkipsMalformedDocuments(t *testing.T) {
	server := newAuditServer(t, auditSearchPayload([]map[string]interface{}{
		{"_id": "bad", "_score": 1.0, "_source": map[string]interface{}{"action": "create_project"}},
		auditHit("evt-1", "2026-09-01T10:00:00Z", []interface{}{"2026-09-01T10:00:00Z", "evt-1"}),
	}, 2, "eq"))
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

// A capped count reported as exact would tell an audit consumer that less happened
// than did. The backend's own relation is passed through.
//
// The gte payload here is the shape OpenSearch really sends once matches exceed the
// track_total_hits bound: {value: <bound>, relation: "gte"}.
func TestQueryAuditLogs_PassesThroughACappedCount(t *testing.T) {
	server := newAuditServer(t, auditSearchPayload([]map[string]interface{}{
		auditHit("evt-1", "2026-09-01T10:00:00Z", []interface{}{"2026-09-01T10:00:00Z", "evt-1"}),
	}, 10000, "gte"))
	defer server.Close()

	resp, err := auditHandler(t, server.URL).QueryAuditLogs(
		context.Background(), gen.QueryAuditLogsRequestObject{Body: auditRequestBody()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	success := resp.(gen.QueryAuditLogs200JSONResponse)
	if success.TotalRelation != "gte" {
		t.Errorf("totalRelation = %q, want gte", success.TotalRelation)
	}
	if success.Total != 10000 {
		t.Errorf("total = %d, want the bound the backend stopped at", success.Total)
	}
}

// track_total_hits must be a bound, not true. With true the backend counts every match
// and always answers relation eq, so a capped count could never be reported - and an
// unbounded count on a year-deep index is the cost the wildcard pattern exists to
// avoid.
func TestQueryAuditLogs_BoundsTheTotalCount(t *testing.T) {
	server := newAuditServer(t, auditSearchPayload(nil, 0, "eq"))
	defer server.Close()

	if _, err := auditHandler(t, server.URL).QueryAuditLogs(
		context.Background(), gen.QueryAuditLogsRequestObject{Body: auditRequestBody()}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, ok := server.searchBody["track_total_hits"]
	if !ok {
		t.Fatal("query does not set track_total_hits")
	}
	if got == true {
		t.Fatal("track_total_hits is true; it must be a bound so a capped count reports gte")
	}
	if got != float64(10000) {
		t.Errorf("track_total_hits = %v, want 10000", got)
	}
}

// Absence of nextCursor is the only end-of-results signal, so a short page must not
// carry one: a caller would otherwise fetch an empty page to discover the end.
func TestQueryAuditLogs_OmitsCursorOnAShortPage(t *testing.T) {
	server := newAuditServer(t, auditSearchPayload([]map[string]interface{}{
		auditHit("evt-1", "2026-09-01T10:00:00Z", []interface{}{"2026-09-01T10:00:00Z", "evt-1"}),
	}, 1, "eq"))
	defer server.Close()

	limit := 10
	body := auditRequestBody()
	body.Limit = &limit

	resp, err := auditHandler(t, server.URL).QueryAuditLogs(
		context.Background(), gen.QueryAuditLogsRequestObject{Body: body})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	success := resp.(gen.QueryAuditLogs200JSONResponse)
	if success.NextCursor != nil {
		t.Errorf("nextCursor = %q on a short page, want none", *success.NextCursor)
	}
}

func TestQueryAuditLogs_MintsACursorOnAFullPage(t *testing.T) {
	server := newAuditServer(t, auditSearchPayload([]map[string]interface{}{
		auditHit("evt-1", "2026-09-01T10:00:00Z", []interface{}{"2026-09-01T10:00:00Z", "evt-1"}),
	}, 5, "eq"))
	defer server.Close()

	limit := 1
	body := auditRequestBody()
	body.Limit = &limit

	resp, err := auditHandler(t, server.URL).QueryAuditLogs(
		context.Background(), gen.QueryAuditLogsRequestObject{Body: body})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	success := resp.(gen.QueryAuditLogs200JSONResponse)
	if success.NextCursor == nil {
		t.Fatal("nextCursor is absent on a full page")
	}

	cursor, err := osearch.DecodeAuditCursor(*success.NextCursor)
	if err != nil {
		t.Fatalf("minted cursor does not decode: %v", err)
	}
	if cursor.PITID != "pit-1" {
		t.Errorf("cursor pit = %q, want the one the cluster echoed", cursor.PITID)
	}
	if len(cursor.SortAfter) != 2 {
		t.Errorf("cursor sort values = %v, want the last hit's", cursor.SortAfter)
	}
}

// An expired cursor is the caller's to act on, so it gets its own status. Answering
// an empty page would read as the end of the trail.
func TestQueryAuditLogs_ExpiredCursorIsGoneNotEmpty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"type":   "search_context_missing_exception",
				"reason": "No search context found for id [42]",
			},
		})
	}))
	defer server.Close()

	cursor, err := osearch.AuditCursor{
		PITID:     "pit-expired",
		SortAfter: []any{"2026-09-01T10:00:00Z", "evt-1"},
	}.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	body := auditRequestBody()
	body.Cursor = &cursor

	resp, err := auditHandler(t, server.URL).QueryAuditLogs(
		context.Background(), gen.QueryAuditLogsRequestObject{Body: body})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(gen.QueryAuditLogs410JSONResponse); !ok {
		t.Fatalf("expected 410 response, got %T", resp)
	}
}

// The timeline covers the whole window, so it is computed once on the first page and
// left off every continuation rather than recomputed per page.
func TestQueryAuditLogs_TimelineOnlyOnTheFirstPage(t *testing.T) {
	payload := auditSearchPayload(nil, 0, "eq")
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

	if _, ok := server.searchBody["aggs"]; !ok {
		t.Error("first page did not request the timeline aggregation")
	}
}

func TestQueryAuditLogs_NoTimelineAggregationWhenPaging(t *testing.T) {
	server := newAuditServer(t, auditSearchPayload(nil, 0, "eq"))
	defer server.Close()

	cursor, err := osearch.AuditCursor{PITID: "pit-1", SortAfter: []any{"x"}}.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	includeTimeline := true
	body := auditRequestBody()
	body.IncludeTimeline = &includeTimeline
	body.Cursor = &cursor

	if _, err := auditHandler(t, server.URL).QueryAuditLogs(
		context.Background(), gen.QueryAuditLogsRequestObject{Body: body}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := server.searchBody["aggs"]; ok {
		t.Error("a continuation page recomputed the timeline")
	}
}

func TestQueryAuditLogFilterValues_RejectsAnUnknownFilter(t *testing.T) {
	handler := NewLogsHandler(nil, nil, nil, nil, 0, nil, testLogger())

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
				"sum_other_doc_count": 0,
			},
			"total_values": map[string]interface{}{"value": 2},
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

// The record query runs against a point-in-time, which must be opened over the audit
// wildcard - not the container logs, and not a day-walked index list.
func TestQueryAuditLogs_OpensThePITOverTheAuditWildcard(t *testing.T) {
	server := newAuditServer(t, auditSearchPayload(nil, 0, "eq"))
	defer server.Close()

	if _, err := auditHandler(t, server.URL).QueryAuditLogs(
		context.Background(), gen.QueryAuditLogsRequestObject{Body: auditRequestBody()}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(server.pitPath, "audit-logs-*") {
		t.Errorf("opened a PIT over %q, want the audit-logs-* pattern", server.pitPath)
	}
	// A PIT search names no index: the point-in-time already carries them.
	if strings.Contains(server.searchPath, "audit-logs-") {
		t.Errorf("PIT search named indices in %q; the PIT carries them", server.searchPath)
	}
}

// The named filter's own selections are ignored so a picker keeps offering the
// alternatives to what is already selected, rather than only the selection itself.
func TestQueryAuditLogFilterValues_IgnoresTheNamedFiltersOwnSelections(t *testing.T) {
	server := newAuditServer(t, map[string]interface{}{
		"took":      2,
		"timed_out": false,
		"hits":      map[string]interface{}{"total": map[string]interface{}{"value": 0, "relation": "eq"}},
		"aggregations": map[string]interface{}{
			"values":       map[string]interface{}{"buckets": []map[string]interface{}{}},
			"total_values": map[string]interface{}{"value": 0},
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

// limit, sortOrder, cursor and the timeline controls carry no meaning here and the
// contract says to ignore them rather than reject them.
func TestQueryAuditLogFilterValues_IgnoresRecordPagingControls(t *testing.T) {
	server := newAuditServer(t, map[string]interface{}{
		"took":      2,
		"timed_out": false,
		"hits":      map[string]interface{}{"total": map[string]interface{}{"value": 0, "relation": "eq"}},
		"aggregations": map[string]interface{}{
			"values":       map[string]interface{}{"buckets": []map[string]interface{}{}},
			"total_values": map[string]interface{}{"value": 0},
		},
	})
	defer server.Close()

	limit := 7
	cursor := "ignored"
	includeTimeline := true
	sortOrder := gen.AuditLogsQueryRequestSortOrder("asc")

	query := *auditRequestBody()
	query.Limit = &limit
	query.Cursor = &cursor
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
