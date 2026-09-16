// Copyright 2026 The OpenChoreo Authors
// SPDX-License-Identifier: Apache-2.0

package openobserve

import (
	"strings"
	"testing"
	"time"
)

var (
	pfStart = time.Date(2026, 8, 14, 16, 30, 0, 0, time.UTC)
	pfEnd   = time.Date(2026, 8, 14, 17, 30, 0, 0, time.UTC)
)

func platformParams() PlatformLogsParams {
	return PlatformLogsParams{StartTime: pfStart, EndTime: pfEnd}
}

func TestMangleLabelKey(t *testing.T) {
	tests := []struct{ in, expected string }{
		{"openchoreo.dev/component-uid", "openchoreo_dev_component_uid"},
		{"app.kubernetes.io/name", "app_kubernetes_io_name"},
		{"pod-template-hash", "pod_template_hash"},
		{"version", "version"},
	}
	for _, tt := range tests {
		if got := mangleLabelKey(tt.in); got != tt.expected {
			t.Errorf("mangleLabelKey(%q) = %q, want %q", tt.in, got, tt.expected)
		}
	}
}

// A key the adapter knows comes back exactly as Kubernetes spells it, so it can be sent
// straight back as a filter. One it does not know keeps its stored spelling rather than
// being guessed at.
func TestRestoreLabelKey(t *testing.T) {
	tests := []struct{ in, expected string }{
		{"kubernetes_labels_openchoreo_dev_component_uid", "openchoreo.dev/component-uid"},
		{"kubernetes_labels_openchoreo_dev_plane", "openchoreo.dev/plane"},
		{"kubernetes_labels_app_kubernetes_io_name", "app.kubernetes.io/name"},
		{"kubernetes_labels_pod_template_hash", "pod-template-hash"},
		{"kubernetes_labels_some_vendor_thing", "some_vendor_thing"},
	}
	for _, tt := range tests {
		if got := restoreLabelKey(tt.in); got != tt.expected {
			t.Errorf("restoreLabelKey(%q) = %q, want %q", tt.in, got, tt.expected)
		}
	}
}

// Every known key must survive the round trip, or it would be listed as restorable while
// actually coming back mangled.
func TestLabelKeyRoundTrip(t *testing.T) {
	for _, key := range knownLabelKeys {
		if got := restoreLabelKey(labelColumnName(key)); got != key {
			t.Errorf("round trip of %q gave %q", key, got)
		}
	}
}

func TestGeneratePlatformLogsQuery(t *testing.T) {
	t.Run("all filters reach the SQL", func(t *testing.T) {
		params := platformParams()
		params.ClusterInstances = []string{"c1", "c2"}
		params.Namespaces = []string{"ns1"}
		params.PodNames = []string{"p1"}
		params.ContainerNames = []string{"ct1"}
		params.Labels = map[string]string{"openchoreo.dev/plane": "dataplane"}
		params.SearchPhrase = "boom"

		raw, err := generatePlatformLogsQuery(params, "default", testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		sql, q := sqlOf(t, raw)

		// Multi-value fields OR within themselves and AND with each other.
		for _, want := range []string{
			`FROM "default"`,
			"(openchoreo_cluster_instance = 'c1' OR openchoreo_cluster_instance = 'c2')",
			"(kubernetes_namespace_name = 'ns1')",
			"(kubernetes_pod_name = 'p1')",
			"(kubernetes_container_name = 'ct1')",
			"\"kubernetes_labels_openchoreo_dev_plane\" = 'dataplane'",
			"log LIKE '%boom%'",
			"ORDER BY _timestamp DESC",
		} {
			if !strings.Contains(sql, want) {
				t.Errorf("expected %q in SQL: %s", want, sql)
			}
		}
		// The time window travels in the envelope, in microseconds, not in the SQL.
		if q["start_time"].(float64) != float64(pfStart.UnixMicro()) {
			t.Errorf("start_time = %v", q["start_time"])
		}
		if q["size"].(float64) != 100 {
			t.Errorf("expected default limit 100, got %v", q["size"])
		}
	})

	t.Run("absent and empty filters are not filters", func(t *testing.T) {
		params := platformParams()
		params.Namespaces = []string{}
		params.Labels = map[string]string{}

		raw, err := generatePlatformLogsQuery(params, "default", testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		sql, _ := sqlOf(t, raw)
		if strings.Contains(sql, "WHERE") {
			t.Errorf("an unfiltered query should have no WHERE clause: %s", sql)
		}
	})

	t.Run("label order is deterministic", func(t *testing.T) {
		params := platformParams()
		params.Labels = map[string]string{"b/x": "2", "a/x": "1", "c/x": "3"}

		var first string
		for i := 0; i < 5; i++ {
			raw, err := generatePlatformLogsQuery(params, "default", testLogger())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			sql, _ := sqlOf(t, raw)
			if i == 0 {
				first = sql
			} else if sql != first {
				t.Fatalf("query differs between calls:\n%s\n%s", first, sql)
			}
		}
	})

	t.Run("sort order is whitelisted, not interpolated", func(t *testing.T) {
		params := platformParams()
		params.SortOrder = "asc; DROP TABLE x"

		raw, err := generatePlatformLogsQuery(params, "default", testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		sql, _ := sqlOf(t, raw)
		if strings.Contains(sql, "DROP TABLE") {
			t.Errorf("sort order was interpolated into SQL: %s", sql)
		}
		if !strings.Contains(sql, "ORDER BY _timestamp DESC") {
			t.Errorf("unrecognised sort order should fall back to DESC: %s", sql)
		}
	})

	// Container logs carry no level column, so severity has to be read from the message.
	t.Run("log levels match the message text", func(t *testing.T) {
		params := platformParams()
		params.LogLevels = []string{"ERROR", "WARN"}

		raw, err := generatePlatformLogsQuery(params, "default", testLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		sql, _ := sqlOf(t, raw)
		if !strings.Contains(sql, "lower(log) LIKE '%error%'") {
			t.Errorf("expected case-insensitive text match on the message: %s", sql)
		}
		if strings.Contains(sql, "logLevel =") {
			t.Errorf("logLevel is not a column the collector emits: %s", sql)
		}
	})
}

// Every user-supplied value is a SQL string literal, so each one is an injection surface.
func TestGeneratePlatformLogsQuery_EscapesEveryFilter(t *testing.T) {
	evil := "' OR 1=1 --"
	params := platformParams()
	params.ClusterInstances = []string{evil}
	params.Namespaces = []string{evil}
	params.PodNames = []string{evil}
	params.ContainerNames = []string{evil}
	params.SearchPhrase = evil
	params.Labels = map[string]string{"k": evil}

	raw, err := generatePlatformLogsQuery(params, "default", testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sql, _ := sqlOf(t, raw)

	// The literal must be quote-opened, contain the input with its quote doubled, and
	// close - so the payload can never terminate the string and become executable.
	for _, want := range []string{
		`openchoreo_cluster_instance = ''' OR 1=1 --'`,
		`kubernetes_namespace_name = ''' OR 1=1 --'`,
		`kubernetes_pod_name = ''' OR 1=1 --'`,
		`kubernetes_container_name = ''' OR 1=1 --'`,
		`"kubernetes_labels_k" = ''' OR 1=1 --'`,
		`log LIKE '%'' OR 1=1 --%'`,
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("expected escaped literal %s in SQL: %s", want, sql)
		}
	}

	// Every quote in the statement must be part of a pair: an odd count means one of them
	// closed a literal early.
	if strings.Count(sql, "'")%2 != 0 {
		t.Errorf("unbalanced quotes, a literal terminated early: %s", sql)
	}
}

func TestGeneratePlatformLogsCountQuery(t *testing.T) {
	params := platformParams()
	params.Namespaces = []string{"ns1"}

	raw, err := generatePlatformLogsCountQuery(params, "default", testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sql, q := sqlOf(t, raw)

	// Aliased to "total" because extractTotalCount reads hits[0]["total"].
	if !strings.Contains(sql, "count(*) as total") {
		t.Errorf("expected an aliased count: %s", sql)
	}
	// The count must carry the same filters, or it would not describe the same records.
	if !strings.Contains(sql, "kubernetes_namespace_name = 'ns1'") {
		t.Errorf("count query lost the filters: %s", sql)
	}
	if q["size"].(float64) != 0 {
		t.Errorf("a count query should return no rows, got size %v", q["size"])
	}
}

func TestParsePlatformLogEntry(t *testing.T) {
	source := map[string]interface{}{
		"log":                                    "something failed",
		"openchoreo_cluster_instance":            "cluster1",
		"kubernetes_namespace_name":              "ns1",
		"kubernetes_pod_name":                    "pod-1",
		"kubernetes_container_name":              "app",
		"kubernetes_pod_ip":                      "10.0.0.1",
		"kubernetes_host":                        "node-1",
		"kubernetes_container_image":             "img:1",
		"kubernetes_labels_openchoreo_dev_plane": "dataplane",
		"kubernetes_labels_some_vendor_thing":    "v",
		"kubernetes_labels_empty":                "",
		"unrelated_column":                       "ignored",
	}

	entry := parsePlatformLogEntry(pfStart.UnixMicro(), source)

	if entry.Log != "something failed" || entry.ClusterInstance != "cluster1" {
		t.Errorf("scalar fields not parsed: %+v", entry)
	}
	if entry.NamespaceName != "ns1" || entry.PodName != "pod-1" || entry.ContainerName != "app" {
		t.Errorf("coordinates not parsed: %+v", entry)
	}
	if entry.PodIP != "10.0.0.1" || entry.NodeName != "node-1" || entry.ContainerImage != "img:1" {
		t.Errorf("pod metadata not parsed: %+v", entry)
	}
	if !entry.Timestamp.Equal(pfStart) {
		t.Errorf("timestamp = %v, want %v", entry.Timestamp, pfStart)
	}
	// Known keys are restored; unknown ones keep their stored spelling; empty and
	// non-label columns are not labels at all.
	if entry.Labels["openchoreo.dev/plane"] != "dataplane" {
		t.Errorf("known label key not restored: %v", entry.Labels)
	}
	if entry.Labels["some_vendor_thing"] != "v" {
		t.Errorf("unknown label key should be carried through: %v", entry.Labels)
	}
	if _, present := entry.Labels["empty"]; present {
		t.Errorf("empty label should be dropped: %v", entry.Labels)
	}
	if len(entry.Labels) != 2 {
		t.Errorf("only label columns should become labels: %v", entry.Labels)
	}
}

// The level filter and extractLogLevel have to agree: a record the filter selects as one
// level must not come back displayed as another, and a record displayed as a level must be
// selectable by that level's filter. Both directions are checked against the classifier
// itself rather than against a hand-written expectation of the SQL.
func TestLogLevelConditionMatchesClassifier(t *testing.T) {
	messages := []string{
		"ERROR something failed",
		"WARN disk nearly full",
		"INFO started",
		"DEBUG cache hit",
		"plain line with no level at all",
		"INFO: retrying after ERROR", // higher precedence wins
		"a FATAL problem",            // classifies as FATAL, not requestable
		"warning: this is a WARNING", // "warn" is reached before "warning"
	}

	for _, level := range []string{"ERROR", "WARN", "INFO", "DEBUG"} {
		cond := logLevelCondition(level)
		if cond == "" {
			t.Fatalf("no condition generated for %s", level)
		}
		for _, msg := range messages {
			selected := evalLogCondition(t, cond, msg)
			classified := extractLogLevel(msg) == level
			if selected != classified {
				t.Errorf("%s filter selects=%v but extractLogLevel gives %q for %q",
					level, selected, extractLogLevel(msg), msg)
			}
		}
	}
}

// evalLogCondition interprets the generated predicate against one message. It understands
// only the shape logLevelCondition emits - a boolean tree of "lower(log) LIKE '%x%'" terms
// combined with AND, OR and NOT - which is enough to check it against the classifier.
func evalLogCondition(t *testing.T, cond, msg string) bool {
	t.Helper()
	lower := strings.ToLower(msg)

	// Each OR-joined clause is a conjunction of possibly negated LIKE terms.
	trimmed := strings.TrimPrefix(strings.TrimSuffix(cond, ")"), "(")
	for _, clause := range splitTopLevel(trimmed, " OR ") {
		clause = strings.TrimPrefix(strings.TrimSuffix(clause, ")"), "(")
		all := true
		for _, term := range splitTopLevel(clause, " AND ") {
			negated := strings.HasPrefix(term, "NOT ")
			term = strings.TrimPrefix(term, "NOT ")
			marker := strings.TrimSuffix(strings.TrimPrefix(term, "lower(log) LIKE '%"), "%'")
			if marker == term {
				t.Fatalf("unrecognised term in generated condition: %q", term)
			}
			if strings.Contains(lower, marker) == negated {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// splitTopLevel splits on sep, ignoring separators nested inside parentheses.
func splitTopLevel(s, sep string) []string {
	var parts []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		}
		if depth == 0 && strings.HasPrefix(s[i:], sep) {
			parts = append(parts, strings.TrimSpace(s[start:i]))
			i += len(sep) - 1
			start = i + 1
		}
	}
	return append(parts, strings.TrimSpace(s[start:]))
}

// An unrequestable or empty level contributes no predicate rather than a false one.
func TestLogLevelCondition_UnknownLevel(t *testing.T) {
	if got := logLevelCondition(""); got != "" {
		t.Errorf("empty level should produce no condition, got %q", got)
	}
	if got := logLevelCondition("TRACE"); got != "" {
		t.Errorf("a level no marker yields should produce no condition, got %q", got)
	}
}

func TestIsValidLabelKey(t *testing.T) {
	valid := []string{
		"openchoreo.dev/component-uid",
		"app.kubernetes.io/name",
		"pod-template-hash",
		"version_id",
		"a",
		// Kubernetes bounds the name at 63 and the prefix at 253, each on its own.
		strings.Repeat("a", 63),
		strings.Repeat("a", 253) + "/name",
		"prefix.io/" + strings.Repeat("a", 63),
	}
	for _, key := range valid {
		if !IsValidLabelKey(key) {
			t.Errorf("IsValidLabelKey(%q) = false, want true", key)
		}
	}

	// A label key becomes a column name, so anything that could carry SQL out of the
	// identifier has to be refused rather than escaped.
	invalid := []string{
		"",
		"x = 1 OR 1=1 OR y",
		"a'b",
		`a"b`,
		"a b",
		"a;b",
		"a(b)",
		"-leading-dash",
		"trailing-dash-",
		strings.Repeat("a", 318),
		// One over each component limit. The whole key is well under 317, so only a
		// per-component check catches these.
		strings.Repeat("a", 64),
		"prefix.io/" + strings.Repeat("a", 64),
		strings.Repeat("a", 254) + "/name",
	}
	for _, key := range invalid {
		if IsValidLabelKey(key) {
			t.Errorf("IsValidLabelKey(%q) = true, want false", key)
		}
	}
}

// Even if a malformed key reached the builder, the column it produces is a single quoted
// identifier and cannot become executable SQL.
func TestLabelColumnIsQuoted(t *testing.T) {
	got := labelColumn("x = 1 OR 1=1 OR y")
	want := `"kubernetes_labels_x = 1 OR 1=1 OR y"`
	if got != want {
		t.Errorf("labelColumn = %s, want %s", got, want)
	}

	// An embedded double quote is doubled, so it cannot close the identifier either.
	if got := labelColumn(`a"b`); got != `"kubernetes_labels_a""b"` {
		t.Errorf("embedded quote not escaped: %s", got)
	}
}
