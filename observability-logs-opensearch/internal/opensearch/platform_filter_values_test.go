// Copyright 2026 The OpenChoreo Authors
// SPDX-License-Identifier: Apache-2.0

package opensearch

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

// termsAgg pulls the terms aggregation body out of a built filter-values query.
func termsAgg(t *testing.T, query map[string]interface{}) map[string]interface{} {
	t.Helper()
	aggs, ok := query["aggs"].(map[string]interface{})
	if !ok {
		t.Fatalf("query has no aggs: %v", query)
	}
	agg, ok := aggs[filterValuesAggName].(map[string]interface{})
	if !ok {
		t.Fatalf("aggs has no %s: %v", filterValuesAggName, aggs)
	}
	terms, ok := agg["terms"].(map[string]interface{})
	if !ok {
		t.Fatalf("agg has no terms: %v", agg)
	}
	return terms
}

func TestPlatformFilterField(t *testing.T) {
	for filter, want := range map[string]string{
		"clusterInstance": "openchoreo_cluster_instance",
		"namespace":       "kubernetes.namespace_name",
		"podName":         "kubernetes.pod_name",
		"containerName":   "kubernetes.container_name",
	} {
		got, ok := PlatformFilterField(filter)
		if !ok || got != want {
			t.Errorf("PlatformFilterField(%q) = %q,%v; want %q,true", filter, got, ok, want)
		}
	}
	// Labels have an open key set, so "which values" has no single answer.
	if _, ok := PlatformFilterField("labels"); ok {
		t.Error("labels should not be listable")
	}
}

// The listed filter's own selections must not constrain its own values, or a choice
// could never be widened once made. Every other filter must still apply.
func TestClearFilterSelections(t *testing.T) {
	base := PlatformLogsQueryParams{
		ClusterInstances: []string{"c1"},
		Namespaces:       []string{"ns1"},
		PodNames:         []string{"p1"},
		ContainerNames:   []string{"ct1"},
	}

	cases := []struct {
		filter  string
		cleared func(PlatformLogsQueryParams) []string
	}{
		{"clusterInstance", func(p PlatformLogsQueryParams) []string { return p.ClusterInstances }},
		{"namespace", func(p PlatformLogsQueryParams) []string { return p.Namespaces }},
		{"podName", func(p PlatformLogsQueryParams) []string { return p.PodNames }},
		{"containerName", func(p PlatformLogsQueryParams) []string { return p.ContainerNames }},
	}
	for _, tc := range cases {
		t.Run(tc.filter, func(t *testing.T) {
			got := ClearFilterSelections(base, tc.filter)
			if v := tc.cleared(got); v != nil {
				t.Errorf("%s: own selections not cleared: %v", tc.filter, v)
			}
			// Exactly one field cleared: the other three still hold one value each.
			remaining := 0
			for _, f := range []([]string){got.ClusterInstances, got.Namespaces, got.PodNames, got.ContainerNames} {
				remaining += len(f)
			}
			if remaining != 3 {
				t.Errorf("%s: expected 3 surviving selections, got %d", tc.filter, remaining)
			}
		})
	}
}

// The other filters must reach the query, so values are drawn only from records the
// caller would actually get back.
func TestBuildPlatformLogFilterValuesQuery_AppliesOtherFilters(t *testing.T) {
	qb := NewQueryBuilder("container-logs-")
	params := PlatformLogsQueryParams{
		StartTime:      "2026-09-01T00:00:00Z",
		EndTime:        "2026-09-02T00:00:00Z",
		Namespaces:     []string{"ns1"},
		ContainerNames: []string{"ct1"},
		Labels:         map[string]string{"openchoreo.dev/plane": "dataplane"},
	}
	query := qb.BuildPlatformLogFilterValuesQuery(params, KubernetesPodName, "", 100)

	conds := platformMustConditions(t, query)
	if findClause(conds, "terms", KubernetesNamespaceName) == nil {
		t.Error("namespace filter did not reach the query")
	}
	if findClause(conds, "terms", KubernetesContainerName) == nil {
		t.Error("containerName filter did not reach the query")
	}
	if findClause(conds, "term", "kubernetes.labels.openchoreo_dev/plane") == nil {
		t.Error("label filter did not reach the query")
	}
	if findClause(conds, "range", "@timestamp") == nil {
		t.Error("time range did not reach the query")
	}
}

// No records are returned, and the agg asks for one bucket more than requested so
// truncation is detectable.
func TestBuildPlatformLogFilterValuesQuery_SizeAndOrder(t *testing.T) {
	qb := NewQueryBuilder("container-logs-")
	query := qb.BuildPlatformLogFilterValuesQuery(PlatformLogsQueryParams{}, KubernetesPodName, "", 25)

	if query["size"] != 0 {
		t.Errorf("expected size 0 (no records), got %v", query["size"])
	}
	terms := termsAgg(t, query)
	if terms["field"] != KubernetesPodName {
		t.Errorf("expected field %q, got %v", KubernetesPodName, terms["field"])
	}
	if terms["size"] != 26 {
		t.Errorf("expected agg size maxValues+1 = 26, got %v", terms["size"])
	}
	order, ok := terms["order"].([]map[string]interface{})
	if !ok || len(order) != 2 {
		t.Fatalf("expected two-key order, got %v", terms["order"])
	}
	if order[0]["_count"] != "desc" || order[1]["_key"] != "asc" {
		t.Errorf("expected count desc then key asc, got %v", order)
	}
	if _, present := terms["include"]; present {
		t.Error("no valueSearch given, include should be absent")
	}
}

// valueSearch must be a literal, case-insensitive substring match - never a regex the
// caller can inject.
func TestContainsRegex(t *testing.T) {
	cases := []struct{ in, want string }{
		{"abc", ".*[Aa][Bb][Cc].*"},
		{"a1", ".*[Aa]1.*"},
		{"a.b", `.*[Aa]\.[Bb].*`},
		{"a*b", `.*[Aa]\*[Bb].*`},
		{"a|b", `.*[Aa]\|[Bb].*`},
		{"-", ".*-.*"},
	}
	for _, tc := range cases {
		if got := containsRegex(tc.in); got != tc.want {
			t.Errorf("containsRegex(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestBuildPlatformLogFilterValuesQuery_ValueSearch(t *testing.T) {
	qb := NewQueryBuilder("container-logs-")
	query := qb.BuildPlatformLogFilterValuesQuery(PlatformLogsQueryParams{}, KubernetesPodName, "Snip", 10)
	if got := termsAgg(t, query)["include"]; got != ".*[Ss][Nn][Ii][Pp].*" {
		t.Errorf("include = %v", got)
	}
}

// buildAggs renders an aggregation response with n buckets.
func buildAggs(n int) json.RawMessage {
	out := `{"filter_values":{"buckets":[`
	for i := 0; i < n; i++ {
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf(`{"key":"v%d","doc_count":%d}`, i, n-i)
	}
	return json.RawMessage(out + `]}}`)
}

// Fewer buckets than asked for means every matching value is present, so the total is
// exact.
func TestParsePlatformLogFilterValues_Exact(t *testing.T) {
	got, err := ParsePlatformLogFilterValues(buildAggs(3), 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.Values) != 3 {
		t.Errorf("expected 3 values, got %d", len(got.Values))
	}
	if got.TotalValues != 3 {
		t.Errorf("every matching value is present, so the total is exact: got %d", got.TotalValues)
	}
	want := []PlatformLogFilterValue{{"v0", 3}, {"v1", 2}, {"v2", 1}}
	if !reflect.DeepEqual(got.Values, want) {
		t.Errorf("values = %v, want %v", got.Values, want)
	}
}

// The extra bucket is never returned; it only says the list was truncated, which makes
// the total a lower bound.
func TestParsePlatformLogFilterValues_Truncated(t *testing.T) {
	got, err := ParsePlatformLogFilterValues(buildAggs(6), 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.Values) != 5 {
		t.Errorf("expected the list capped at 5, got %d", len(got.Values))
	}
	if got.TotalValues != 6 {
		t.Errorf("truncated, so the total is a floor of 6: got %d", got.TotalValues)
	}
}

// Exactly maxValues buckets means nothing was cut off.
func TestParsePlatformLogFilterValues_ExactlyAtLimit(t *testing.T) {
	got, err := ParsePlatformLogFilterValues(buildAggs(5), 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.TotalValues != 5 {
		t.Errorf("nothing was cut off, so the total is exact: got %d", got.TotalValues)
	}
}

// No filter value would select an empty string, so such a bucket is not offered.
func TestParsePlatformLogFilterValues_SkipsEmptyValue(t *testing.T) {
	raw := json.RawMessage(`{"filter_values":{"buckets":[{"key":"","doc_count":9},{"key":"v","doc_count":1}]}}`)
	got, err := ParsePlatformLogFilterValues(raw, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.Values) != 1 || got.Values[0].Value != "v" {
		t.Errorf("expected only the non-empty value, got %v", got.Values)
	}
}

// OpenSearch omits aggregations when every index the query named is absent - a window
// outside retention, say. That is an empty answer, not a failure; erroring here would
// turn an ordinary empty result into a 500.
func TestParsePlatformLogFilterValues_NoAggregations(t *testing.T) {
	got, err := ParsePlatformLogFilterValues(nil, 10)
	if err != nil {
		t.Fatalf("absent aggregations should not be an error: %v", err)
	}
	if len(got.Values) != 0 || got.TotalValues != 0 {
		t.Errorf("expected empty/0, got %v/%d", got.Values, got.TotalValues)
	}
}

// A non-empty but unparseable aggregation body is a real failure and must surface.
func TestParsePlatformLogFilterValues_MalformedAggregations(t *testing.T) {
	if _, err := ParsePlatformLogFilterValues(json.RawMessage(`{"filter_values":`), 10); err == nil {
		t.Error("expected an error for a malformed aggregation body")
	}
}

// An aggregation with no buckets is an empty list, not an error.
func TestParsePlatformLogFilterValues_EmptyBuckets(t *testing.T) {
	got, err := ParsePlatformLogFilterValues(json.RawMessage(`{"filter_values":{"buckets":[]}}`), 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.Values) != 0 || got.TotalValues != 0 {
		t.Errorf("expected empty/0, got %v/%d", got.Values, got.TotalValues)
	}
}
