// Copyright 2026 The OpenChoreo Authors
// SPDX-License-Identifier: Apache-2.0

package openobserve

import (
	"strings"
	"testing"
)

func TestPlatformFilterField(t *testing.T) {
	for filter, expected := range map[string]string{
		"clusterInstance": "openchoreo_cluster_instance",
		"namespace":       "kubernetes_namespace_name",
		"podName":         "kubernetes_pod_name",
		"containerName":   "kubernetes_container_name",
	} {
		got, ok := PlatformFilterField(filter)
		if !ok || got != expected {
			t.Errorf("PlatformFilterField(%q) = %q,%v; want %q,true", filter, got, ok, expected)
		}
	}
	// Pod labels have an open key set, so "which values" has no single answer.
	if _, ok := PlatformFilterField("labels"); ok {
		t.Error("labels should not be listable")
	}
}

// The listed filter's own selections must not constrain its own values, or a choice could
// never be widened once made. Every other filter must still apply.
func TestClearFilterSelections(t *testing.T) {
	base := PlatformLogsParams{
		ClusterInstances: []string{"c1"},
		Namespaces:       []string{"ns1"},
		PodNames:         []string{"p1"},
		ContainerNames:   []string{"ct1"},
	}
	cases := []struct {
		filter  string
		cleared func(PlatformLogsParams) []string
	}{
		{"clusterInstance", func(p PlatformLogsParams) []string { return p.ClusterInstances }},
		{"namespace", func(p PlatformLogsParams) []string { return p.Namespaces }},
		{"podName", func(p PlatformLogsParams) []string { return p.PodNames }},
		{"containerName", func(p PlatformLogsParams) []string { return p.ContainerNames }},
	}
	for _, tc := range cases {
		t.Run(tc.filter, func(t *testing.T) {
			got := ClearFilterSelections(base, tc.filter)
			if v := tc.cleared(got); v != nil {
				t.Errorf("own selections not cleared: %v", v)
			}
			remaining := 0
			for _, f := range [][]string{got.ClusterInstances, got.Namespaces, got.PodNames, got.ContainerNames} {
				remaining += len(f)
			}
			if remaining != 3 {
				t.Errorf("expected 3 surviving selections, got %d", remaining)
			}
		})
	}
}

func TestGeneratePlatformFilterValuesQuery(t *testing.T) {
	t.Run("groups and orders by count then value", func(t *testing.T) {
		params := platformParams()
		params.Namespaces = []string{"ns1"}

		raw, err := generatePlatformFilterValuesQuery(params, "default", colPodName, "", 25, testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		sql, q := sqlOf(t, raw)

		for _, want := range []string{
			"SELECT kubernetes_pod_name as value, count(*) as count",
			`FROM "default"`,
			"GROUP BY kubernetes_pod_name",
			"ORDER BY count(*) DESC, kubernetes_pod_name ASC",
			"LIMIT 25",
			// Other filters still narrow which records the values come from.
			"kubernetes_namespace_name = 'ns1'",
			// A value no filter could select is not offered.
			"kubernetes_pod_name IS NOT NULL",
			"kubernetes_pod_name != ''",
		} {
			if !strings.Contains(sql, want) {
				t.Errorf("expected %q in SQL: %s", want, sql)
			}
		}
		if q["size"].(float64) != 25 {
			t.Errorf("envelope size should match the limit, got %v", q["size"])
		}
		// No records are returned, so nothing is ordered by time.
		if strings.Contains(sql, "ORDER BY _timestamp") {
			t.Errorf("filter values should not order records: %s", sql)
		}
	})

	t.Run("total query counts distinct under identical conditions", func(t *testing.T) {
		params := platformParams()
		params.Namespaces = []string{"ns1"}

		raw, err := generatePlatformFilterValuesTotalQuery(params, "default", colPodName, "", testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		sql, q := sqlOf(t, raw)

		if !strings.Contains(sql, "count(distinct kubernetes_pod_name) as total") {
			t.Errorf("expected an exact distinct count: %s", sql)
		}
		// If the two queries disagreed on conditions, the total would not describe the list.
		for _, want := range []string{"kubernetes_namespace_name = 'ns1'", "kubernetes_pod_name IS NOT NULL"} {
			if !strings.Contains(sql, want) {
				t.Errorf("total query lost a condition %q: %s", want, sql)
			}
		}
		if q["size"].(float64) != 0 {
			t.Errorf("a count query should return no rows, got size %v", q["size"])
		}
	})
}

// valueSearch narrows the values, case-insensitively, and matches literally - a value
// containing a wildcard must not silently become a pattern.
func TestValueSearchIsALiteralCaseInsensitiveMatch(t *testing.T) {
	tests := []struct {
		name, search, expected string
	}{
		{"lowercased", "Snip", "lower(kubernetes_pod_name) LIKE '%snip%' ESCAPE '!'"},
		{"percent escaped", "50%", "lower(kubernetes_pod_name) LIKE '%50!%%' ESCAPE '!'"},
		{"underscore escaped", "a_b", "lower(kubernetes_pod_name) LIKE '%a!_b%' ESCAPE '!'"},
		{"escape char escaped", "a!b", "lower(kubernetes_pod_name) LIKE '%a!!b%' ESCAPE '!'"},
		{"quote escaped", "o'brien", "lower(kubernetes_pod_name) LIKE '%o''brien%' ESCAPE '!'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := generatePlatformFilterValuesQuery(
				platformParams(), "default", colPodName, tt.search, 10, testLogger())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			sql, _ := sqlOf(t, raw)
			if !strings.Contains(sql, tt.expected) {
				t.Errorf("expected %q in SQL: %s", tt.expected, sql)
			}
		})
	}
}

// The same escaping must reach the total query, or the two would count different things.
func TestValueSearchAppliesToTotalQuery(t *testing.T) {
	raw, err := generatePlatformFilterValuesTotalQuery(
		platformParams(), "default", colPodName, "50%", testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sql, _ := sqlOf(t, raw)
	if !strings.Contains(sql, "LIKE '%50!%%' ESCAPE '!'") {
		t.Errorf("value search did not reach the total query: %s", sql)
	}
}

func TestParsePlatformFilterValues(t *testing.T) {
	resp := &OpenObserveResponse{Hits: []map[string]interface{}{
		{"value": "b", "count": float64(9)},
		{"value": "a", "count": float64(4)},
		{"value": "", "count": float64(3)},
		{"count": float64(1)},
	}}

	values := parsePlatformFilterValues(resp)

	if len(values) != 2 {
		t.Fatalf("rows without a usable value should be dropped, got %+v", values)
	}
	if values[0].Value != "b" || values[0].Count != 9 {
		t.Errorf("first value = %+v", values[0])
	}
	if values[1].Value != "a" || values[1].Count != 4 {
		t.Errorf("second value = %+v", values[1])
	}
}

// A stream that has never been written to is an empty answer, not a failure.
func TestParsePlatformFilterValues_NoHits(t *testing.T) {
	values := parsePlatformFilterValues(&OpenObserveResponse{Hits: []map[string]interface{}{}})
	if len(values) != 0 {
		t.Errorf("expected no values, got %+v", values)
	}
}
