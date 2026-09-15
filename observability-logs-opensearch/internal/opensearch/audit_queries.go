// Copyright 2026 The OpenChoreo Authors
// SPDX-License-Identifier: Apache-2.0

package opensearch

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// AuditEventTimeField is when the audited request was received. Filtering and sorting
// use it rather than @timestamp, which is when the collector read the line.
const AuditEventTimeField = "event_time"

// AuditEventIDField is a UUID v7, unique per record.
const AuditEventIDField = "event_id"

// AuditEntitlementValuesField holds the values of every claim in the record's
// actor.entitlements map, copied there by the index template, so a caller can filter on
// an entitlement without knowing which claim carries it.
const AuditEntitlementValuesField = "actor.entitlement_values"

// maxTimelineBuckets is the ceiling the contract requires a wider request to be
// coarsened to rather than rejected against.
const maxTimelineBuckets = 500

// maxAggregationRegexLength is OpenSearch's index.max_regex_length default.
const maxAggregationRegexLength = 1000

// auditTrackTotalHits counts every match rather than stopping at OpenSearch's default
// 10000: the contract specifies total as exact and offers no way to mark one truncated.
const auditTrackTotalHits = true

// AuditLogsQueryParams holds the filters for an audit log query.
type AuditLogsQueryParams struct {
	StartTime string
	EndTime   string

	ActorIDs          []string
	ActorTypes        []string
	ActorIssuers      []string
	ActorSessionIDs   []string
	ActorEntitlements []string

	ResourceTypes        []string
	ResourceNamespaces   []string
	ResourceEnvironments []string
	ResourceProjects     []string
	ResourceComponents   []string
	ResourceNames        []string

	Actions      []string
	Categories   []string
	Results      []string
	Producers    []string
	Surfaces     []string
	OperationIDs []string
	RequestIDs   []string
	EventIDs     []string
	SourceIPs    []string
	UserAgents   []string

	SearchPhrase string
	Limit        int
	SortOrder    string
}

// AuditIndexPattern returns the wildcard the audit indices are searched through.
//
// A wildcard rather than GenerateIndices' day-by-day enumeration: audit retention
// defaults to a year, and a year of daily index names is ~8KB of request line against
// OpenSearch's 4KB default, which fails as a malformed request rather than a length
// error.
func (qb *QueryBuilder) AuditIndexPattern() string {
	return qb.indexPrefix + "*"
}

// BuildAuditLogsQuery builds the search body for an audit log query.
func (qb *QueryBuilder) BuildAuditLogsQuery(params AuditLogsQueryParams) map[string]interface{} {
	filters := auditFilters(params)

	limit := params.Limit
	if limit <= 0 {
		limit = 100
	}
	sortOrder := params.SortOrder
	if sortOrder == "" {
		sortOrder = "desc"
	}

	return map[string]interface{}{
		"size": limit,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": filters,
			},
		},
		"sort":             auditSort(sortOrder),
		"track_total_hits": auditTrackTotalHits,
	}
}

// auditSort breaks event_time ties on event_id, so records sharing a timestamp come
// back in a stable order across identical queries.
func auditSort(sortOrder string) []map[string]interface{} {
	return []map[string]interface{}{
		{AuditEventTimeField: map[string]interface{}{"order": sortOrder}},
		{AuditEventIDField: map[string]interface{}{"order": sortOrder}},
	}
}

func auditFilters(params AuditLogsQueryParams) []map[string]interface{} {
	filters := []map[string]interface{}{}
	filters = addAuditTimeRangeFilter(filters, params.StartTime, params.EndTime)

	filters = addTermsFilter(filters, "actor.id", params.ActorIDs)
	filters = addTermsFilter(filters, "actor.type", params.ActorTypes)
	filters = addTermsFilter(filters, "actor.issuer", params.ActorIssuers)
	filters = addTermsFilter(filters, "actor.session_id", params.ActorSessionIDs)
	filters = addTermsFilter(filters, AuditEntitlementValuesField, params.ActorEntitlements)

	filters = addTermsFilter(filters, "resource.type", params.ResourceTypes)
	filters = addTermsFilter(filters, "resource.namespace", params.ResourceNamespaces)
	filters = addTermsFilter(filters, "resource.environment", params.ResourceEnvironments)
	filters = addTermsFilter(filters, "resource.project", params.ResourceProjects)
	filters = addTermsFilter(filters, "resource.component", params.ResourceComponents)
	filters = addTermsFilter(filters, "resource.name", params.ResourceNames)

	filters = addTermsFilter(filters, "action", params.Actions)
	filters = addTermsFilter(filters, "category", params.Categories)
	filters = addTermsFilter(filters, "result", params.Results)
	filters = addTermsFilter(filters, "producer", params.Producers)
	filters = addTermsFilter(filters, "surface", params.Surfaces)
	filters = addTermsFilter(filters, "operation_id", params.OperationIDs)
	filters = addTermsFilter(filters, "request_id", params.RequestIDs)
	filters = addTermsFilter(filters, AuditEventIDField, params.EventIDs)
	filters = addTermsFilter(filters, "source_ip", params.SourceIPs)
	filters = addTermsFilter(filters, "user_agent", params.UserAgents)

	filters = addSearchPhraseFilter(filters, params.SearchPhrase)

	return filters
}

// addAuditTimeRangeFilter bounds the query on event_time, inclusive of startTime and
// exclusive of endTime as the contract states.
func addAuditTimeRangeFilter(
	filters []map[string]interface{}, startTime, endTime string,
) []map[string]interface{} {
	if startTime == "" || endTime == "" {
		return filters
	}
	return append(filters, map[string]interface{}{
		"range": map[string]interface{}{
			AuditEventTimeField: map[string]interface{}{
				"gte": startTime,
				"lt":  endTime,
			},
		},
	})
}

// BuildAuditTimelineAgg builds the date histogram that backs the timeline.
//
// min_doc_count 0 with extended_bounds keeps empty buckets, which the contract
// requires: a sparse array would let a caller chart straight across a gap in activity.
func BuildAuditTimelineAgg(interval, startTime, endTime string) map[string]interface{} {
	return map[string]interface{}{
		"timeline": map[string]interface{}{
			"date_histogram": map[string]interface{}{
				"field":          AuditEventTimeField,
				"fixed_interval": interval,
				"min_doc_count":  0,
				"extended_bounds": map[string]interface{}{
					"min": startTime,
					"max": endTime,
				},
			},
			"aggs": map[string]interface{}{
				"results": map[string]interface{}{
					"terms": map[string]interface{}{
						"field": "result",
						"size":  20,
					},
				},
			},
		},
	}
}

// ResolveTimelineInterval picks the bucket width to use.
//
// A width exceeding maxTimelineBuckets is coarsened rather than rejected: rejecting
// would leave a caller who asked for 1m over a year with no timeline at all.
func ResolveTimelineInterval(requested string, start, end time.Time) (string, error) {
	window := end.Sub(start)
	if window <= 0 {
		return "", fmt.Errorf("end time must be after start time")
	}

	width, err := parseTimelineInterval(requested)
	if err != nil {
		return "", err
	}
	if width <= 0 {
		width = window / 60
		if width < time.Minute {
			width = time.Minute
		}
	}

	// Ceiling, because a window that does not divide evenly spills into one more bucket
	// than the floor reports.
	for (window+width-1)/width > maxTimelineBuckets {
		next := coarsenInterval(width)
		if next <= width {
			// Already at the coarsest unit, so widen in whole weeks.
			width += 7 * 24 * time.Hour
			continue
		}
		width = next
	}

	return formatTimelineInterval(width), nil
}

// parseTimelineInterval reads the contract's <count><unit> notation. An empty string
// means the adapter chooses, and is not an error.
func parseTimelineInterval(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid timeline interval: %s", s)
	}

	count, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || count <= 0 {
		return 0, fmt.Errorf("invalid timeline interval: %s", s)
	}

	var unit time.Duration
	switch s[len(s)-1] {
	case 'm':
		unit = time.Minute
	case 'h':
		unit = time.Hour
	case 'd':
		unit = 24 * time.Hour
	case 'w':
		unit = 7 * 24 * time.Hour
	default:
		return 0, fmt.Errorf("invalid timeline interval unit: %s", s)
	}

	return time.Duration(count) * unit, nil
}

// coarsenInterval steps up to the next unit, returning d unchanged at the coarsest one.
func coarsenInterval(d time.Duration) time.Duration {
	switch {
	case d < time.Hour:
		return time.Hour
	case d < 24*time.Hour:
		return 24 * time.Hour
	case d < 7*24*time.Hour:
		return 7 * 24 * time.Hour
	}
	return d
}

// formatTimelineInterval renders a duration into the contract's notation.
//
// Weeks are rendered as a day count because OpenSearch's fixed_interval accepts no
// unit above d.
func formatTimelineInterval(d time.Duration) string {
	switch {
	case d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	default:
		minutes := int(d / time.Minute)
		if minutes < 1 {
			minutes = 1
		}
		return fmt.Sprintf("%dm", minutes)
	}
}

// BuildAuditFilterValuesQuery builds the search body for a filter's distinct values.
// The caller drops the named filter's own selections from params first.
func (qb *QueryBuilder) BuildAuditFilterValuesQuery(
	params AuditLogsQueryParams, field string, valueSearch string, maxValues int,
) map[string]interface{} {
	if maxValues <= 0 {
		maxValues = 100
	}

	terms := map[string]interface{}{
		"field": field,
		"size":  maxValues,
		// Busiest first, so a truncated list holds the useful end of it.
		"order": []map[string]string{
			{"_count": "desc"},
			{"_key": "asc"},
		},
	}
	// The cardinality is scoped to the same search the buckets are, so the count reports
	// how many values match rather than how many the field holds. Nesting it under its
	// own filter keeps the bucket doc counts drawn from the unnarrowed record set.
	totalScope := map[string]interface{}{"match_all": map[string]interface{}{}}
	if include, ok := valueSearchRegex(valueSearch); ok {
		terms["include"] = include
		totalScope = map[string]interface{}{
			"regexp": map[string]interface{}{field: include},
		}
	}

	return map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": auditFilters(params),
			},
		},
		"aggs": map[string]interface{}{
			"values": map[string]interface{}{
				"terms": terms,
			},
			"total_values": map[string]interface{}{
				"filter": totalScope,
				"aggs": map[string]interface{}{
					"matching": map[string]interface{}{
						"cardinality": map[string]interface{}{
							"field": field,
						},
					},
				},
			},
		},
	}
}

// valueSearchRegex turns a case-insensitive substring search into the Lucene regex a
// terms aggregation include takes, reporting false when it would be too long to send.
//
// Each cased letter expands into a character class because the engine has no (?i)
// flag. A lowercase normalizer sub-field would be simpler but returns lowercased
// values, and the contract requires values to come back exactly as they would be sent
// back as a filter.
func valueSearchRegex(valueSearch string) (string, bool) {
	if valueSearch == "" {
		return "", false
	}

	var b strings.Builder
	b.WriteString(".*")
	for _, r := range valueSearch {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteString("[" + string(r) + string(r-32) + "]")
		case r >= 'A' && r <= 'Z':
			b.WriteString("[" + string(r+32) + string(r) + "]")
		default:
			b.WriteString(escapeRegexLiteral(r))
		}
	}
	b.WriteString(".*")

	if b.Len() > maxAggregationRegexLength {
		return "", false
	}
	return b.String(), true
}

// escapeRegexLiteral quotes a character that would otherwise be regex syntax.
func escapeRegexLiteral(r rune) string {
	const meta = `.?+*|{}[]()"\#@&<>~`
	if strings.ContainsRune(meta, r) {
		return `\` + string(r)
	}
	return string(r)
}

// ParseAuditFilterValues reads the values aggregation back out of a search response,
// returning the distinct values and how many distinct values matched in total.
func ParseAuditFilterValues(aggregations json.RawMessage) ([]AuditFilterValue, int64, error) {
	if len(aggregations) == 0 {
		return nil, 0, nil
	}

	var parsed struct {
		Values struct {
			Buckets []struct {
				Key      string `json:"key"`
				DocCount int64  `json:"doc_count"`
			} `json:"buckets"`
		} `json:"values"`
		TotalValues struct {
			Matching struct {
				Value int64 `json:"value"`
			} `json:"matching"`
		} `json:"total_values"`
	}
	if err := json.Unmarshal(aggregations, &parsed); err != nil {
		return nil, 0, fmt.Errorf("failed to parse filter value aggregation: %w", err)
	}

	values := make([]AuditFilterValue, 0, len(parsed.Values.Buckets))
	for _, bucket := range parsed.Values.Buckets {
		// No filter value would select an empty key, so it is not offered as a choice.
		if bucket.Key == "" {
			continue
		}
		values = append(values, AuditFilterValue{Value: bucket.Key, Count: bucket.DocCount})
	}

	return values, parsed.TotalValues.Matching.Value, nil
}

// ParseAuditTimeline reads the timeline aggregation back out of a search response,
// returning nil when the response carries none — a different answer from a timeline
// reporting no activity.
func ParseAuditTimeline(aggregations json.RawMessage, interval string) (*AuditTimeline, error) {
	if len(aggregations) == 0 {
		return nil, nil
	}

	var parsed struct {
		Timeline struct {
			Buckets []struct {
				KeyAsString string `json:"key_as_string"`
				DocCount    int64  `json:"doc_count"`
				Results     struct {
					Buckets []struct {
						Key      string `json:"key"`
						DocCount int64  `json:"doc_count"`
					} `json:"buckets"`
				} `json:"results"`
			} `json:"buckets"`
		} `json:"timeline"`
	}
	if err := json.Unmarshal(aggregations, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse timeline aggregation: %w", err)
	}
	if parsed.Timeline.Buckets == nil {
		return nil, nil
	}

	buckets := make([]AuditTimelineBucket, 0, len(parsed.Timeline.Buckets))
	for _, b := range parsed.Timeline.Buckets {
		startTime, err := time.Parse(time.RFC3339, b.KeyAsString)
		if err != nil {
			return nil, fmt.Errorf("failed to parse timeline bucket start %q: %w", b.KeyAsString, err)
		}

		counts := make(map[string]int64, len(b.Results.Buckets))
		for _, r := range b.Results.Buckets {
			counts[r.Key] = r.DocCount
		}

		buckets = append(buckets, AuditTimelineBucket{
			StartTime: startTime,
			Total:     b.DocCount,
			Counts:    counts,
		})
	}

	return &AuditTimeline{Interval: interval, Buckets: buckets}, nil
}

// FilterValuesBySearch applies a case-insensitive substring match in Go, for the
// searches too long to express as an aggregation regex.
func FilterValuesBySearch(values []AuditFilterValue, valueSearch string) []AuditFilterValue {
	if valueSearch == "" {
		return values
	}
	needle := strings.ToLower(valueSearch)
	filtered := make([]AuditFilterValue, 0, len(values))
	for _, v := range values {
		if strings.Contains(strings.ToLower(v.Value), needle) {
			filtered = append(filtered, v)
		}
	}
	return filtered
}
