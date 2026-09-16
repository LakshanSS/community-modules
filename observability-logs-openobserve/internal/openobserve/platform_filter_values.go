// Copyright 2026 The OpenChoreo Authors
// SPDX-License-Identifier: Apache-2.0

package openobserve

import (
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"
)

// DefaultMaxFilterValues is the number of values returned when the caller does not ask for
// a count. It matches the contract's default.
const DefaultMaxFilterValues = 100

// MaxMaxFilterValues is the ceiling the contract puts on maxValues.
const MaxMaxFilterValues = 1000

// likeEscapeChar escapes LIKE's own wildcards inside a value search.
//
// "!" rather than the conventional "\": escapeSQLString doubles backslashes on their way
// into the string literal, so a backslash escape would arrive at LIKE already mangled.
const likeEscapeChar = "!"

// platformFilterFields maps a filter, named as the request field that accepts it, onto the
// column it selects on.
//
// Only these four are listable. Pod labels are deliberately absent: the set of label keys
// is open, so "which values does this filter take" has no single answer for them.
var platformFilterFields = map[string]string{
	"clusterInstance": ClusterInstanceField,
	"namespace":       colNamespaceName,
	"podName":         colPodName,
	"containerName":   colContainerName,
}

// PlatformFilterField returns the column a filter selects on, and whether the filter is one
// this adapter can list.
func PlatformFilterField(filter string) (string, bool) {
	column, ok := platformFilterFields[filter]
	return column, ok
}

// PlatformLogFilterValue is one value a filter takes, with how many records carry it.
type PlatformLogFilterValue struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

// PlatformLogFilterValues is the parsed result of a filter-values query.
type PlatformLogFilterValues struct {
	Values      []PlatformLogFilterValue `json:"values"`
	TotalValues int64                    `json:"totalValues"`
	Took        int                      `json:"took"`
}

// ClearFilterSelections returns params with the named filter's own selections removed.
//
// The values a filter can take are those reachable under the query's *other* filters. A
// filter that counted its own selection would only ever offer back what is already picked,
// so a choice could never be widened once made.
func ClearFilterSelections(params PlatformLogsParams, filter string) PlatformLogsParams {
	switch filter {
	case "clusterInstance":
		params.ClusterInstances = nil
	case "namespace":
		params.Namespaces = nil
	case "podName":
		params.PodNames = nil
	case "containerName":
		params.ContainerNames = nil
	}
	return params
}

// filterValuesConditions builds the WHERE clauses both filter-values queries share.
//
// The record filters are the same ones the log query applies, so the values offered are
// exactly those reachable from the records the caller would get back. Rows where the column
// is absent or empty are dropped: no filter value would select one, so offering it would
// give the caller a choice that matches nothing. Both queries must apply this identically,
// or the total would not agree with the list it describes.
func filterValuesConditions(params PlatformLogsParams, column, valueSearch string) []string {
	conditions := buildPlatformConditions(params)
	conditions = append(conditions, column+" IS NOT NULL", column+" != ''")
	if valueSearch != "" {
		conditions = append(conditions, containsCondition(column, valueSearch))
	}
	return conditions
}

// containsCondition matches rows whose column contains text, case-insensitively.
//
// The value is matched literally: LIKE's own wildcards are escaped, so a search for "50%"
// finds the text "50%" rather than everything beginning "50". Without that a value search
// would quietly behave as a pattern the caller never asked for.
func containsCondition(column, text string) string {
	escaped := escapeSQLString(escapeLikeWildcards(strings.ToLower(text)))
	return "lower(" + column + ") LIKE '%" + escaped + "%' ESCAPE '" + likeEscapeChar + "'"
}

// escapeLikeWildcards neutralises LIKE's wildcards, and the escape character itself.
func escapeLikeWildcards(value string) string {
	return strings.NewReplacer(
		likeEscapeChar, likeEscapeChar+likeEscapeChar,
		"%", likeEscapeChar+"%",
		"_", likeEscapeChar+"_",
	).Replace(value)
}

// generatePlatformFilterValuesQuery builds the query listing the values one filter takes.
//
// LIMIT bounds the grouped rows rather than the envelope's size, which is a page size over
// returned hits; the envelope is set to match so neither can truncate below the other.
func generatePlatformFilterValuesQuery(
	params PlatformLogsParams, stream, column, valueSearch string, maxValues int, logger *slog.Logger,
) ([]byte, error) {
	conditions := filterValuesConditions(params, column, valueSearch)

	sql := "SELECT " + column + " as value, count(*) as count FROM " + quoteIdentifier(stream) +
		whereClause(conditions) +
		" GROUP BY " + column +
		// Busiest first, ties broken by value so the order is stable across calls. Ordered
		// by the expressions rather than the aliases: "count" is also a function name, and
		// an alias that shadows one is needlessly ambiguous.
		" ORDER BY count(*) DESC, " + column + " ASC" +
		" LIMIT " + strconv.Itoa(maxValues)

	query := platformQueryEnvelope(sql, params, maxValues)

	logPlatformQuery(logger, "platform log filter values", query)
	return json.Marshal(query)
}

// generatePlatformFilterValuesTotalQuery counts the distinct values matching the same
// conditions.
//
// SQL can answer this exactly, so the contract's totalValues is a true count rather than
// the lower bound a backend without distinct counting would have to report.
func generatePlatformFilterValuesTotalQuery(
	params PlatformLogsParams, stream, column, valueSearch string, logger *slog.Logger,
) ([]byte, error) {
	conditions := filterValuesConditions(params, column, valueSearch)

	sql := "SELECT count(distinct " + column + ") as total FROM " + quoteIdentifier(stream) +
		whereClause(conditions)

	query := platformQueryEnvelope(sql, params, 0)

	logPlatformQuery(logger, "platform log filter values total", query)
	return json.Marshal(query)
}

// parsePlatformFilterValues reads the grouped rows back.
//
// OpenObserve returns GROUP BY results as ordinary rows, so there is no aggregation
// envelope to unwrap - each hit is one value and its count.
func parsePlatformFilterValues(resp *OpenObserveResponse) []PlatformLogFilterValue {
	values := make([]PlatformLogFilterValue, 0, len(resp.Hits))
	for _, hit := range resp.Hits {
		value, ok := hit["value"].(string)
		if !ok || value == "" {
			continue
		}
		count := int64(0)
		if c, ok := hit["count"].(float64); ok {
			count = int64(c)
		}
		values = append(values, PlatformLogFilterValue{Value: value, Count: count})
	}
	return values
}
