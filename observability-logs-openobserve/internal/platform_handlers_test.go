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

	"github.com/openchoreo/community-modules/observability-logs-openobserve/internal/api/gen"
	"github.com/openchoreo/community-modules/observability-logs-openobserve/internal/openobserve"
)

var (
	pfStart = time.Date(2026, 8, 14, 16, 30, 0, 0, time.UTC)
	pfEnd   = time.Date(2026, 8, 14, 17, 30, 0, 0, time.UTC)
)

// platformServer stands in for OpenObserve. It records every SQL statement it is sent, and
// answers count queries with a total and everything else with the given hits - the adapter
// makes two round trips per request, so the two have to be told apart.
func platformServer(t *testing.T, sqls *[]string, hits []map[string]interface{}, total int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		var parsed map[string]interface{}
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Errorf("parse request body: %v", err)
		}
		query, _ := parsed["query"].(map[string]interface{})
		sql, _ := query["sql"].(string)
		if sqls != nil {
			*sqls = append(*sqls, sql)
		}

		// Both count queries alias their result to "total"; the values query aliases to
		// "value"/"count". Discriminating on "count(" alone would misroute the values
		// query, which also selects count(*).
		resp := map[string]interface{}{"took": 7, "hits": hits}
		if strings.Contains(sql, "as total") {
			resp["hits"] = []map[string]interface{}{{"total": total}}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func platformHandler(t *testing.T, serverURL string) *LogsHandler {
	t.Helper()
	return NewLogsHandler(
		openobserve.NewClient(serverURL, "default", "default", "k8s_events", "admin", "token", testLogger()),
		nil, testLogger(),
	)
}

func platformLogsRequest() gen.QueryPlatformLogsRequestObject {
	return gen.QueryPlatformLogsRequestObject{
		Body: &gen.PlatformLogsQueryRequest{StartTime: pfStart, EndTime: pfEnd},
	}
}

func filterValuesRequest(filter gen.PlatformLogFilterValuesRequestFilter) gen.QueryPlatformLogFilterValuesRequestObject {
	return gen.QueryPlatformLogFilterValuesRequestObject{
		Body: &gen.PlatformLogFilterValuesRequest{
			Filter: filter,
			Query:  gen.PlatformLogsQueryRequest{StartTime: pfStart, EndTime: pfEnd},
		},
	}
}

func TestQueryPlatformLogs_NilBody(t *testing.T) {
	handler := NewLogsHandler(nil, nil, testLogger())
	resp, err := handler.QueryPlatformLogs(context.Background(), gen.QueryPlatformLogsRequestObject{Body: nil})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(gen.QueryPlatformLogs400JSONResponse); !ok {
		t.Fatalf("expected 400 response, got %T", resp)
	}
}

func TestQueryPlatformLogs_Success(t *testing.T) {
	server := platformServer(t, nil, []map[string]interface{}{{
		"_timestamp":                             float64(pfStart.UnixMicro()),
		"log":                                    "ERROR something failed",
		"openchoreo_cluster_instance":            "cluster1",
		"kubernetes_namespace_name":              "ns1",
		"kubernetes_pod_name":                    "pod-1",
		"kubernetes_container_name":              "app",
		"kubernetes_pod_ip":                      "10.0.0.1",
		"kubernetes_host":                        "node-1",
		"kubernetes_container_image":             "img:1",
		"kubernetes_labels_openchoreo_dev_plane": "dataplane",
	}}, 42)
	defer server.Close()

	resp, err := platformHandler(t, server.URL).QueryPlatformLogs(context.Background(), platformLogsRequest())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ok, is := resp.(gen.QueryPlatformLogs200JSONResponse)
	if !is {
		t.Fatalf("expected 200 response, got %T", resp)
	}
	if len(ok.Logs) != 1 {
		t.Fatalf("expected one log, got %d", len(ok.Logs))
	}
	entry := ok.Logs[0]
	if entry.Log != "ERROR something failed" {
		t.Errorf("log = %q", entry.Log)
	}
	if entry.ClusterInstance == nil || *entry.ClusterInstance != "cluster1" {
		t.Errorf("clusterInstance not carried through")
	}
	if entry.NodeName == nil || *entry.NodeName != "node-1" {
		t.Errorf("nodeName not carried through")
	}
	// The label key is handed back in Kubernetes spelling so it can be sent back as a filter.
	if entry.Labels == nil || (*entry.Labels)["openchoreo.dev/plane"] != "dataplane" {
		t.Errorf("labels = %v", entry.Labels)
	}
	// Total comes from the second round trip, not from the size of the page.
	if ok.Total != 42 {
		t.Errorf("total = %d, want 42", ok.Total)
	}
}

func TestQueryPlatformLogs_SearchFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	resp, err := platformHandler(t, server.URL).QueryPlatformLogs(context.Background(), platformLogsRequest())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(gen.QueryPlatformLogs500JSONResponse); !ok {
		t.Fatalf("expected 500 response, got %T", resp)
	}
}

func TestQueryPlatformLogFilterValues_NilBody(t *testing.T) {
	handler := NewLogsHandler(nil, nil, testLogger())
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
	handler := NewLogsHandler(nil, nil, testLogger())
	resp, err := handler.QueryPlatformLogFilterValues(context.Background(), filterValuesRequest("labels"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(gen.QueryPlatformLogFilterValues400JSONResponse); !ok {
		t.Fatalf("expected 400 response, got %T", resp)
	}
}

func TestQueryPlatformLogFilterValues_Success(t *testing.T) {
	server := platformServer(t, nil, []map[string]interface{}{
		{"value": "ns-b", "count": float64(9)},
		{"value": "ns-a", "count": float64(4)},
	}, 2)
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

// The listed filter's own selections are dropped, while the other filters still narrow the
// records the values are drawn from.
func TestQueryPlatformLogFilterValues_DropsOwnSelections(t *testing.T) {
	var sqls []string
	server := platformServer(t, &sqls, nil, 0)
	defer server.Close()

	req := filterValuesRequest(gen.Namespace)
	namespaces := []string{"ns-already-picked"}
	pods := []string{"pod-1"}
	req.Body.Query.Namespace = &namespaces
	req.Body.Query.PodName = &pods

	if _, err := platformHandler(t, server.URL).QueryPlatformLogFilterValues(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sqls) == 0 {
		t.Fatal("no query was issued")
	}
	for _, sql := range sqls {
		if strings.Contains(sql, "ns-already-picked") {
			t.Errorf("namespace selections should not constrain namespace values: %s", sql)
		}
		if !strings.Contains(sql, "pod-1") {
			t.Errorf("other filters should still apply: %s", sql)
		}
	}
}

// limit and sortOrder page and order records; this endpoint returns none, so they are
// ignored rather than rejected.
func TestQueryPlatformLogFilterValues_IgnoresLimitAndSortOrder(t *testing.T) {
	var sqls []string
	server := platformServer(t, &sqls, nil, 0)
	defer server.Close()

	req := filterValuesRequest(gen.PodName)
	limit := 777
	order := gen.PlatformLogsQueryRequestSortOrder("asc")
	req.Body.Query.Limit = &limit
	req.Body.Query.SortOrder = &order

	if _, err := platformHandler(t, server.URL).QueryPlatformLogFilterValues(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, sql := range sqls {
		if strings.Contains(sql, "ORDER BY _timestamp") {
			t.Errorf("record ordering should not appear: %s", sql)
		}
		if strings.Contains(sql, "LIMIT 777") {
			t.Errorf("query.limit is a record page size and must be ignored: %s", sql)
		}
	}
}

func TestQueryPlatformLogFilterValues_ClampsMaxValues(t *testing.T) {
	var sqls []string
	server := platformServer(t, &sqls, nil, 0)
	defer server.Close()

	req := filterValuesRequest(gen.PodName)
	tooMany := 99999
	req.Body.MaxValues = &tooMany

	if _, err := platformHandler(t, server.URL).QueryPlatformLogFilterValues(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, sql := range sqls {
		if strings.Contains(sql, "LIMIT 1000") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected maxValues clamped to 1000: %v", sqls)
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

// A label key becomes a column name, so it cannot be escaped into safety the way a value
// can. A malformed key is refused rather than dropped: dropping it would widen the query
// and return records the caller never asked for.
func TestQueryPlatformLogs_RejectsMalformedLabelKey(t *testing.T) {
	handler := NewLogsHandler(nil, nil, testLogger())

	req := platformLogsRequest()
	labels := map[string]string{"x = 1 OR 1=1 OR y": "v"}
	req.Body.Labels = &labels

	resp, err := handler.QueryPlatformLogs(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(gen.QueryPlatformLogs400JSONResponse); !ok {
		t.Fatalf("expected 400 response, got %T", resp)
	}
}

func TestQueryPlatformLogFilterValues_RejectsMalformedLabelKey(t *testing.T) {
	handler := NewLogsHandler(nil, nil, testLogger())

	req := filterValuesRequest(gen.Namespace)
	labels := map[string]string{"a'b": "v"}
	req.Body.Query.Labels = &labels

	resp, err := handler.QueryPlatformLogFilterValues(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(gen.QueryPlatformLogFilterValues400JSONResponse); !ok {
		t.Fatalf("expected 400 response, got %T", resp)
	}
}

// A well-formed key still reaches the backend.
func TestQueryPlatformLogs_AcceptsValidLabelKey(t *testing.T) {
	var sqls []string
	server := platformServer(t, &sqls, nil, 0)
	defer server.Close()

	req := platformLogsRequest()
	labels := map[string]string{"openchoreo.dev/plane": "dataplane"}
	req.Body.Labels = &labels

	resp, err := platformHandler(t, server.URL).QueryPlatformLogs(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := resp.(gen.QueryPlatformLogs200JSONResponse); !ok {
		t.Fatalf("expected 200 response, got %T", resp)
	}
	if len(sqls) == 0 || !strings.Contains(sqls[0], `"kubernetes_labels_openchoreo_dev_plane" = 'dataplane'`) {
		t.Errorf("label filter did not reach the query: %v", sqls)
	}
}
