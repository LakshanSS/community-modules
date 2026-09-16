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

	"github.com/openchoreo/community-modules/observability-logs-opensearch/internal/api/gen"
)

// filterValuesServer stands in for OpenSearch, returning the given terms buckets and
// recording the query body it was sent.
func filterValuesServer(t *testing.T, captured *map[string]interface{}, buckets []map[string]interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if captured != nil {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read request body: %v", err)
			}
			var parsed map[string]interface{}
			if err := json.Unmarshal(body, &parsed); err != nil {
				t.Errorf("parse request body: %v", err)
			}
			*captured = parsed
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"took":      7,
			"timed_out": false,
			"hits": map[string]interface{}{
				"total": map[string]interface{}{"value": 0, "relation": "eq"},
				"hits":  []map[string]interface{}{},
			},
			"aggregations": map[string]interface{}{
				"filter_values": map[string]interface{}{"buckets": buckets},
			},
		})
	}))
}

func filterValuesRequest(filter gen.PlatformLogFilterValuesRequestFilter) gen.QueryPlatformLogFilterValuesRequestObject {
	return gen.QueryPlatformLogFilterValuesRequestObject{
		Body: &gen.PlatformLogFilterValuesRequest{
			Filter: filter,
			Query: gen.PlatformLogsQueryRequest{
				StartTime: platformStart,
				EndTime:   platformEnd,
			},
		},
	}
}

func TestQueryPlatformLogFilterValues_NilBody(t *testing.T) {
	handler := NewLogsHandler(nil, nil, nil, nil, nil, testLogger())

	resp, err := handler.QueryPlatformLogFilterValues(
		context.Background(), gen.QueryPlatformLogFilterValuesRequestObject{Body: nil})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(gen.QueryPlatformLogFilterValues400JSONResponse); !ok {
		t.Fatalf("expected 400 response, got %T", resp)
	}
}

// A filter this adapter cannot list is refused, rather than answered with an empty list
// that would read as "no values".
func TestQueryPlatformLogFilterValues_UnlistableFilter(t *testing.T) {
	handler := NewLogsHandler(nil, nil, nil, nil, nil, testLogger())

	resp, err := handler.QueryPlatformLogFilterValues(
		context.Background(), filterValuesRequest("labels"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(gen.QueryPlatformLogFilterValues400JSONResponse); !ok {
		t.Fatalf("expected 400 response, got %T", resp)
	}
}

func TestQueryPlatformLogFilterValues_Success(t *testing.T) {
	server := filterValuesServer(t, nil, []map[string]interface{}{
		{"key": "ns-b", "doc_count": 9},
		{"key": "ns-a", "doc_count": 4},
	})
	defer server.Close()

	resp, err := platformHandler(t, server.URL).QueryPlatformLogFilterValues(
		context.Background(), filterValuesRequest(gen.Namespace))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ok, is := resp.(gen.QueryPlatformLogFilterValues200JSONResponse)
	if !is {
		t.Fatalf("expected 200 response, got %T", resp)
	}
	if ok.Filter != "namespace" {
		t.Errorf("filter should be echoed, got %q", ok.Filter)
	}
	if len(ok.Values) != 2 || ok.Values[0].Value != "ns-b" || ok.Values[0].Count != 9 {
		t.Errorf("values = %+v", ok.Values)
	}
	if ok.TotalValues != 2 {
		t.Errorf("totalValues = %d, want 2", ok.TotalValues)
	}
	if ok.TookMs != 7 {
		t.Errorf("tookMs = %d, want 7", ok.TookMs)
	}
}

// The listed filter's own selections are dropped, while the other filters still narrow
// the records the values are drawn from.
func TestQueryPlatformLogFilterValues_DropsOwnSelections(t *testing.T) {
	var captured map[string]interface{}
	server := filterValuesServer(t, &captured, nil)
	defer server.Close()

	req := filterValuesRequest(gen.Namespace)
	namespaces := []string{"ns-already-picked"}
	pods := []string{"pod-1"}
	req.Body.Query.Namespace = &namespaces
	req.Body.Query.PodName = &pods

	if _, err := platformHandler(t, server.URL).QueryPlatformLogFilterValues(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body, err := json.Marshal(captured)
	if err != nil {
		t.Fatalf("marshal captured query: %v", err)
	}
	if bytes := string(body); strings.Contains(bytes, "ns-already-picked") {
		t.Errorf("namespace selections should not constrain namespace values: %s", bytes)
	} else if !strings.Contains(bytes, "pod-1") {
		t.Errorf("other filters should still apply: %s", bytes)
	}
}

// limit and sortOrder page and order records; this endpoint returns none, so they are
// ignored rather than rejected.
func TestQueryPlatformLogFilterValues_IgnoresLimitAndSortOrder(t *testing.T) {
	var captured map[string]interface{}
	server := filterValuesServer(t, &captured, nil)
	defer server.Close()

	req := filterValuesRequest(gen.PodName)
	limit := 777
	order := gen.PlatformLogsQueryRequestSortOrder("asc")
	req.Body.Query.Limit = &limit
	req.Body.Query.SortOrder = &order

	if _, err := platformHandler(t, server.URL).QueryPlatformLogFilterValues(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured["size"] != float64(0) {
		t.Errorf("expected size 0 regardless of query.limit, got %v", captured["size"])
	}
	if _, present := captured["sort"]; present {
		t.Error("no records are returned, so the query should carry no sort")
	}
}

// maxValues is clamped to the contract's ceiling, and the aggregation asks for one more
// than that so truncation stays detectable.
func TestQueryPlatformLogFilterValues_ClampsMaxValues(t *testing.T) {
	var captured map[string]interface{}
	server := filterValuesServer(t, &captured, nil)
	defer server.Close()

	req := filterValuesRequest(gen.PodName)
	tooMany := 99999
	req.Body.MaxValues = &tooMany

	if _, err := platformHandler(t, server.URL).QueryPlatformLogFilterValues(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	aggs := captured["aggs"].(map[string]interface{})
	terms := aggs["filter_values"].(map[string]interface{})["terms"].(map[string]interface{})
	if terms["size"] != float64(1001) {
		t.Errorf("expected clamped size 1000+1, got %v", terms["size"])
	}
}

func TestQueryPlatformLogFilterValues_SearchFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	resp, err := platformHandler(t, server.URL).QueryPlatformLogFilterValues(
		context.Background(), filterValuesRequest(gen.PodName))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(gen.QueryPlatformLogFilterValues500JSONResponse); !ok {
		t.Fatalf("expected 500 response, got %T", resp)
	}
}
