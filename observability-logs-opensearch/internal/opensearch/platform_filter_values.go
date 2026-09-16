// Copyright 2026 The OpenChoreo Authors
// SPDX-License-Identifier: Apache-2.0

package opensearch

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
)

// filterValuesAggName is the name of the terms aggregation the filter-values query asks
// for, and the key its response is read back under.
const filterValuesAggName = "filter_values"

// DefaultMaxFilterValues is the number of values returned when the caller does not ask
// for a count. It matches the contract's default.
const DefaultMaxFilterValues = 100

// MaxMaxFilterValues is the ceiling the contract puts on maxValues.
const MaxMaxFilterValues = 1000

// platformFilterFields maps a filter, named as the request field that accepts it, onto
// the record field it selects on. Only these four are listable: each is a keyword with
// doc values, so a terms aggregation over it is cheap. Labels are deliberately absent -
// the set of label keys is open, so "which values does a filter take" has no single
// answer for them.
var platformFilterFields = map[string]string{
	"clusterInstance": ClusterInstanceField,
	"namespace":       KubernetesNamespaceName,
	"podName":         KubernetesPodName,
	"containerName":   KubernetesContainerName,
}

// PlatformFilterField returns the record field a filter selects on, and whether the
// filter is one this adapter can list.
func PlatformFilterField(filter string) (string, bool) {
	field, ok := platformFilterFields[filter]
	return field, ok
}

// PlatformLogFilterValue is one value a filter takes, with how many records carry it.
type PlatformLogFilterValue struct {
	Value string
	Count int64
}

// PlatformLogFilterValues is the parsed result of a filter-values query.
type PlatformLogFilterValues struct {
	Values      []PlatformLogFilterValue
	TotalValues int64
}

// ClearFilterSelections returns params with the named filter's own selections removed.
//
// The values a filter can take are those reachable under the query's *other* filters. A
// filter that counted its own selection would only ever offer back what is already
// picked, so the UI could never widen a choice once made.
func ClearFilterSelections(params PlatformLogsQueryParams, filter string) PlatformLogsQueryParams {
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

// BuildPlatformLogFilterValuesQuery builds the aggregation that lists the values one
// filter takes under a query.
//
// The record filters are the same ones BuildPlatformLogsQuery applies, so the values
// offered are exactly those reachable from the records the caller would get back - minus
// the listed filter's own selections, which the caller is expected to have cleared with
// ClearFilterSelections.
//
// size is one more than asked for. That extra bucket is never returned; it is how the
// caller learns the list was truncated, which is the difference between reporting
// "exactly this many values" and "at least one more than these". The contract treats
// TotalValues as a sense of scale, so a bound is an acceptable answer and one extra
// bucket is a cheaper way to get it than a separate distinct-count aggregation.
func (qb *QueryBuilder) BuildPlatformLogFilterValuesQuery(
	params PlatformLogsQueryParams, field, valueSearch string, maxValues int,
) map[string]interface{} {
	mustConditions := []map[string]interface{}{}
	mustConditions = addTimeRangeFilter(mustConditions, params.StartTime, params.EndTime)
	mustConditions = addTermsFilter(mustConditions, ClusterInstanceField, params.ClusterInstances)
	mustConditions = addTermsFilter(mustConditions, KubernetesNamespaceName, params.Namespaces)
	mustConditions = addTermsFilter(mustConditions, KubernetesPodName, params.PodNames)
	mustConditions = addTermsFilter(mustConditions, KubernetesContainerName, params.ContainerNames)
	mustConditions = addLabelFilters(mustConditions, params.Labels)
	mustConditions = addSearchPhraseFilter(mustConditions, params.SearchPhrase)
	mustConditions = addLogLevelFilter(mustConditions, params.LogLevels)

	terms := map[string]interface{}{
		"field": field,
		"size":  maxValues + 1,
		// Busiest first, ties broken by value so the order is stable across calls.
		"order": []map[string]interface{}{
			{"_count": "desc"},
			{"_key": "asc"},
		},
	}
	if valueSearch != "" {
		terms["include"] = containsRegex(valueSearch)
	}

	return map[string]interface{}{
		// No records are returned, only the values: this is a count, not a page.
		"size": 0,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": mustConditions,
			},
		},
		"aggs": map[string]interface{}{
			filterValuesAggName: map[string]interface{}{
				"terms": terms,
			},
		},
	}
}

// containsRegex builds a Lucene regex matching any term containing s, case-insensitively.
//
// A terms aggregation's include is anchored, hence the leading and trailing .*. Lucene
// regex has no inline case-insensitivity flag, so each cased letter becomes a two-element
// character class. Everything reserved is escaped, so a value search is always a literal
// substring match and never a regex the caller can inject.
func containsRegex(s string) string {
	var b strings.Builder
	b.WriteString(".*")
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) && unicode.ToLower(r) != unicode.ToUpper(r):
			b.WriteByte('[')
			b.WriteRune(unicode.ToUpper(r))
			b.WriteRune(unicode.ToLower(r))
			b.WriteByte(']')
		case strings.ContainsRune(`.?+*|{}[]()"\#@&<>~`, r):
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteString(".*")
	return b.String()
}

// termsAggResponse is the shape of the terms aggregation this module asks for.
type termsAggResponse struct {
	Buckets []struct {
		Key      string `json:"key"`
		DocCount int64  `json:"doc_count"`
	} `json:"buckets"`
}

// ParsePlatformLogFilterValues reads the terms aggregation back.
//
// The query asks for maxValues+1 buckets. Getting that many back means at least one more
// value exists than was asked for, so the list is truncated to maxValues and the total is
// reported as a floor. Fewer means every matching value is present and the total is exact.
func ParsePlatformLogFilterValues(raw json.RawMessage, maxValues int) (*PlatformLogFilterValues, error) {
	// OpenSearch omits aggregations entirely when every index the query named is absent,
	// which is the ordinary answer for a window older than retention or newer than the
	// first record. No values exist to offer, and that is a result, not a failure.
	if len(raw) == 0 {
		return &PlatformLogFilterValues{
			Values:      []PlatformLogFilterValue{},
			TotalValues: 0,
		}, nil
	}

	var aggs struct {
		FilterValues termsAggResponse `json:"filter_values"`
	}
	if err := json.Unmarshal(raw, &aggs); err != nil {
		return nil, fmt.Errorf("decoding aggregations: %w", err)
	}

	buckets := aggs.FilterValues.Buckets
	truncated := len(buckets) > maxValues
	if truncated {
		buckets = buckets[:maxValues]
	}

	values := make([]PlatformLogFilterValue, 0, len(buckets))
	for _, b := range buckets {
		// A record on which the field is absent contributes no bucket, but an explicit
		// empty value would, and no filter value would select one.
		if b.Key == "" {
			continue
		}
		values = append(values, PlatformLogFilterValue{Value: b.Key, Count: b.DocCount})
	}

	result := &PlatformLogFilterValues{
		Values:      values,
		TotalValues: int64(len(values)),
	}
	if truncated {
		// One more is known to exist; how many more is not, so this is a floor rather
		// than a count.
		result.TotalValues = int64(len(values)) + 1
	}
	return result, nil
}
