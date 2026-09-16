// Copyright 2026 The OpenChoreo Authors
// SPDX-License-Identifier: Apache-2.0

package openobserve

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"
)

// PlatformLogsParams holds parameters for a platform log query.
//
// Every filter is optional except the time range. Multi-value fields OR within themselves
// and AND with each other, and an absent or empty field is not a filter - the distinction
// that decides whether an unfiltered query returns everything or nothing.
type PlatformLogsParams struct {
	ClusterInstances []string          `json:"clusterInstances,omitempty"`
	Namespaces       []string          `json:"namespaces,omitempty"`
	PodNames         []string          `json:"podNames,omitempty"`
	ContainerNames   []string          `json:"containerNames,omitempty"`
	Labels           map[string]string `json:"labels,omitempty"`
	StartTime        time.Time         `json:"startTime"`
	EndTime          time.Time         `json:"endTime"`
	SearchPhrase     string            `json:"searchPhrase,omitempty"`
	LogLevels        []string          `json:"logLevels,omitempty"`
	Limit            int               `json:"limit,omitempty"`
	SortOrder        string            `json:"sortOrder,omitempty"`
}

// PlatformLogsEntry is a parsed platform log record: the message plus the physical
// coordinates and pod metadata of whatever produced it.
type PlatformLogsEntry struct {
	Timestamp       time.Time         `json:"timestamp"`
	Log             string            `json:"log"`
	LogLevel        string            `json:"logLevel"`
	ClusterInstance string            `json:"clusterInstance"`
	NamespaceName   string            `json:"namespaceName"`
	PodName         string            `json:"podName"`
	ContainerName   string            `json:"containerName"`
	PodIP           string            `json:"podIp"`
	NodeName        string            `json:"nodeName"`
	ContainerImage  string            `json:"containerImage"`
	Labels          map[string]string `json:"labels,omitempty"`
}

// PlatformLogsResult is a page of platform logs plus the true total.
type PlatformLogsResult struct {
	Logs       []PlatformLogsEntry `json:"logs"`
	TotalCount int                 `json:"totalCount"`
	Took       int                 `json:"took"`
}

// buildPlatformConditions assembles the WHERE clauses shared by the record query, the
// count query and the filter-values queries. Keeping them in one place is what guarantees
// the values offered for a filter are drawn from the records the caller would get back.
func buildPlatformConditions(params PlatformLogsParams) []string {
	var conditions []string

	conditions = appendInCondition(conditions, ClusterInstanceField, params.ClusterInstances)
	conditions = appendInCondition(conditions, colNamespaceName, params.Namespaces)
	conditions = appendInCondition(conditions, colPodName, params.PodNames)
	conditions = appendInCondition(conditions, colContainerName, params.ContainerNames)

	// Label keys are sorted so the same filters always produce the same SQL: Go randomises
	// map iteration, so without this the query differs between calls and cannot be compared
	// in a test or matched in a log.
	if len(params.Labels) > 0 {
		keys := make([]string, 0, len(params.Labels))
		for k := range params.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			conditions = append(conditions,
				labelColumn(k)+" = '"+escapeSQLString(params.Labels[k])+"'")
		}
	}

	if params.SearchPhrase != "" {
		conditions = append(conditions, "log LIKE '%"+escapeSQLString(params.SearchPhrase)+"%'")
	}

	// Log level is read out of the message text, not off a column: the collector emits no
	// level field for container logs, so a record's severity is only ever what its own text
	// says. The predicate has to agree with extractLogLevel, which decides the level shown
	// in the response - otherwise a record could be filtered in as INFO and then displayed
	// as ERROR, or excluded by the filter that matches the level it is labelled with.
	if len(params.LogLevels) > 0 {
		levelConditions := make([]string, 0, len(params.LogLevels))
		for _, level := range params.LogLevels {
			if cond := logLevelCondition(level); cond != "" {
				levelConditions = append(levelConditions, cond)
			}
		}
		if len(levelConditions) > 0 {
			conditions = append(conditions, "("+strings.Join(levelConditions, " OR ")+")")
		}
	}

	return conditions
}

// appendInCondition ORs the given values on one column. An empty slice is not a filter.
func appendInCondition(conditions []string, column string, values []string) []string {
	if len(values) == 0 {
		return conditions
	}
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, column+" = '"+escapeSQLString(v)+"'")
	}
	return append(conditions, "("+strings.Join(parts, " OR ")+")")
}

// whereClause renders conditions as a WHERE suffix, or "" when there are none.
func whereClause(conditions []string) string {
	if len(conditions) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(conditions, " AND ")
}

// platformQueryEnvelope wraps SQL in the body OpenObserve's _search endpoint expects. The
// time window is carried here rather than in the SQL, as microseconds since epoch.
func platformQueryEnvelope(sql string, params PlatformLogsParams, size int) map[string]interface{} {
	return map[string]interface{}{
		"query": map[string]interface{}{
			"sql":        sql,
			"start_time": params.StartTime.UnixMicro(),
			"end_time":   params.EndTime.UnixMicro(),
			"from":       0,
			"size":       size,
		},
	}
}

// generatePlatformLogsQuery builds the query for a page of platform logs.
func generatePlatformLogsQuery(params PlatformLogsParams, stream string, logger *slog.Logger) ([]byte, error) {
	sql := "SELECT * FROM " + quoteIdentifier(stream) + whereClause(buildPlatformConditions(params))

	// Whitelisted rather than interpolated: this sits outside quotes, where an arbitrary
	// string would be executable.
	if strings.EqualFold(params.SortOrder, "asc") {
		sql += " ORDER BY " + colTimestamp + " ASC"
	} else {
		sql += " ORDER BY " + colTimestamp + " DESC"
	}

	limit := params.Limit
	if limit <= 0 {
		limit = 100
	}

	query := platformQueryEnvelope(sql, params, limit)
	query["timeout"] = 0

	logPlatformQuery(logger, "platform logs", query)
	return json.Marshal(query)
}

// generatePlatformLogsCountQuery builds the companion count query.
//
// OpenObserve's search response reports the size of the page it returned, so the true
// number of matching records takes a second query - the same two-round-trip shape the
// component and workflow log queries already use.
func generatePlatformLogsCountQuery(params PlatformLogsParams, stream string, logger *slog.Logger) ([]byte, error) {
	sql := "SELECT count(*) as total FROM " + quoteIdentifier(stream) +
		whereClause(buildPlatformConditions(params))

	query := platformQueryEnvelope(sql, params, 0)

	logPlatformQuery(logger, "platform logs count", query)
	return json.Marshal(query)
}

// logPlatformQuery prints a generated query when debug logging is on.
func logPlatformQuery(logger *slog.Logger, label string, query map[string]interface{}) {
	if logger == nil || !logger.Enabled(nil, slog.LevelDebug) {
		return
	}
	if prettyJSON, err := json.MarshalIndent(query, "", "    "); err == nil {
		fmt.Printf("Generated %s query:\n%s\n", label, string(prettyJSON))
	}
}

// parsePlatformLogEntry turns one OpenObserve row into a platform log entry.
//
// Every column beginning with the pod-label prefix is carried through, so a record's
// labels are whatever it was stored with rather than a fixed list this adapter knows.
func parsePlatformLogEntry(timestamp int64, source map[string]interface{}) PlatformLogsEntry {
	entry := PlatformLogsEntry{Timestamp: time.UnixMicro(timestamp)}

	if v, ok := source[colLog].(string); ok {
		entry.Log = v
	}
	if v, ok := source[ClusterInstanceField].(string); ok {
		entry.ClusterInstance = v
	}
	if v, ok := source[colNamespaceName].(string); ok {
		entry.NamespaceName = v
	}
	if v, ok := source[colPodName].(string); ok {
		entry.PodName = v
	}
	if v, ok := source[colContainerName].(string); ok {
		entry.ContainerName = v
	}
	if v, ok := source[colPodIP].(string); ok {
		entry.PodIP = v
	}
	if v, ok := source[colHost].(string); ok {
		entry.NodeName = v
	}
	if v, ok := source[colContainerImage].(string); ok {
		entry.ContainerImage = v
	}

	// The collector emits no level field for container logs, so severity is read from the
	// message, and left empty when the text does not say.
	entry.LogLevel = extractLogLevel(entry.Log)

	for column, raw := range source {
		if !strings.HasPrefix(column, labelColumnPrefix) {
			continue
		}
		value, ok := raw.(string)
		if !ok || value == "" {
			continue
		}
		if entry.Labels == nil {
			entry.Labels = make(map[string]string)
		}
		entry.Labels[restoreLabelKey(column)] = value
	}

	return entry
}

// logLevelMarkers are the substrings extractLogLevel scans for, in the order it scans them,
// with the level each yields. "warning" is absent because "warn" precedes it and is a
// prefix of it, so it can never be reached.
var logLevelMarkers = []struct{ marker, level string }{
	{"error", "ERROR"},
	{"fatal", "FATAL"},
	{"severe", "SEVERE"},
	{"warn", "WARN"},
	{"info", "INFO"},
	{"debug", "DEBUG"},
}

// defaultLogLevel is what extractLogLevel returns for a message carrying no marker at all.
const defaultLogLevel = "INFO"

// logLevelCondition matches the records extractLogLevel would classify as the given level.
//
// Classification is first-match-wins down logLevelMarkers, so a level is selected by its
// own marker being present and every higher-precedence marker being absent - a line reading
// "INFO: retrying after ERROR" is an ERROR, and an INFO filter must not return it. The
// level a message with no marker falls back to also has to match those messages, or a
// filter would exclude records the response labels with that very level.
func logLevelCondition(level string) string {
	level = strings.ToUpper(strings.TrimSpace(level))
	if level == "" {
		return ""
	}

	var own []string
	var higher []string
	for _, m := range logLevelMarkers {
		if m.level == level {
			own = append(own, m.marker)
			continue
		}
		if len(own) == 0 {
			higher = append(higher, m.marker)
		}
	}

	var clauses []string
	if len(own) > 0 {
		clause := logContains(own[0])
		for _, h := range higher {
			clause += " AND NOT " + logContains(h)
		}
		clauses = append(clauses, "("+clause+")")
	}

	// A message with no marker is classified as the default level, so that level's filter
	// has to select those messages too.
	if level == defaultLogLevel {
		absent := make([]string, 0, len(logLevelMarkers))
		for _, m := range logLevelMarkers {
			absent = append(absent, "NOT "+logContains(m.marker))
		}
		clauses = append(clauses, "("+strings.Join(absent, " AND ")+")")
	}

	if len(clauses) == 0 {
		return ""
	}
	return "(" + strings.Join(clauses, " OR ") + ")"
}

// logContains matches a lowercase marker anywhere in the message.
func logContains(marker string) string {
	return "lower(" + colLog + ") LIKE '%" + marker + "%'"
}
