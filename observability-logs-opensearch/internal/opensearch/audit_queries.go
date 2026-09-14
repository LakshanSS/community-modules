// Copyright 2026 The OpenChoreo Authors
// SPDX-License-Identifier: Apache-2.0

package opensearch

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// AuditEventTimeField is the record's own time: when the audited request was
// received. Filtering and sorting use it rather than @timestamp, which is when the
// collector read the line and is what picks the daily index. The two normally differ
// by milliseconds, and by much more when collection was backed up.
const AuditEventTimeField = "event_time"

// AuditEventIDField is a UUID v7, unique per record, so it breaks ties between two
// records sharing an event_time deterministically. Sorting on event_time alone would
// let a page boundary fall inside a group of equal timestamps and repeat or skip
// records across pages.
const AuditEventIDField = "event_id"

// AuditEntitlementValuesField holds the values of every claim in the record's
// actor.entitlements map, copied there by the index template. Both the entitlement
// filter and its value picker read it: the claim key varies by subject kind, and a
// caller filtering on an entitlement should not have to know which claim carries it.
const AuditEntitlementValuesField = "actor.entitlement_values"

// maxTimelineBuckets caps how many buckets a timeline may hold. The contract requires
// a request that would exceed it to be coarsened rather than rejected.
const maxTimelineBuckets = 500

// maxAggregationRegexLength is OpenSearch's index.max_regex_length default. A terms
// aggregation include is a Lucene regex and is rejected outright above it.
const maxAggregationRegexLength = 1000

// auditTotalHitsCap bounds how far the backend counts matches.
//
// A bound rather than `true`: counting without one is an unbounded pass over a
// year-deep index on every broad query, which is the cost the wildcard index pattern
// exists to avoid. Below the cap OpenSearch reports an exact count and relation `eq`;
// above it, `{value: <cap>, relation: "gte"}` - which is what lets the response say
// honestly that more happened than it counted, rather than passing a capped figure off
// as exact.
const auditTotalHitsCap = 10000

// AuditLogsQueryParams holds the filters for an audit log query. Each field maps onto
// one stored field, named as the record names it, so a rename on either side shows up
// here rather than being absorbed by a lookup table.
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

// AuditCursor pins one page of results to a point in time, so a record written
// mid-scroll cannot shift a page boundary. It is encoded opaquely: the contract
// deliberately leaves the shape unspecified so it does not pick a storage backend.
type AuditCursor struct {
	PITID     string `json:"pit"`
	SortAfter []any  `json:"after"`
	SortOrder string `json:"order"`
}

// Encode renders the cursor as the opaque token the contract passes around.
func (c AuditCursor) Encode() (string, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("failed to encode cursor: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// DecodeAuditCursor parses a token minted by Encode.
func DecodeAuditCursor(token string) (AuditCursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return AuditCursor{}, fmt.Errorf("failed to decode cursor: %w", err)
	}
	var cursor AuditCursor
	if err := json.Unmarshal(raw, &cursor); err != nil {
		return AuditCursor{}, fmt.Errorf("failed to parse cursor: %w", err)
	}
	if cursor.PITID == "" {
		return AuditCursor{}, fmt.Errorf("cursor carries no point-in-time id")
	}
	return cursor, nil
}

// AuditIndexPattern returns the wildcard the audit indices are searched through.
//
// Deliberately not a day-by-day enumeration like GenerateIndices: audit retention
// defaults to a year, and a year of daily index names is roughly 8KB of request line
// against OpenSearch's 4KB default limit — which fails as a malformed request rather
// than as a length error. The event_time range filter selects the same records, and a
// point-in-time opened against a wildcard resolves its indices once at open time,
// which is what keeps a page boundary stable while a new daily index appears.
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
		"track_total_hits": auditTotalHitsCap,
	}
}

// auditSort orders by event time, then by event id to break ties.
func auditSort(sortOrder string) []map[string]interface{} {
	return []map[string]interface{}{
		{AuditEventTimeField: map[string]interface{}{"order": sortOrder}},
		{AuditEventIDField: map[string]interface{}{"order": sortOrder}},
	}
}

// auditFilters maps the params onto one clause per populated filter. Multi-value
// fields OR within themselves through a single terms clause and AND with each other
// by sitting side by side in the filter array; an empty field adds no clause.
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

// addAuditTimeRangeFilter bounds the query on the record's own event time.
// startTime is inclusive and endTime exclusive, as the contract states.
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

// BuildAuditTimelineAgg builds the date histogram that backs the timeline, broken
// down by result.
//
// min_doc_count 0 and extended_bounds together make the buckets contiguous across the
// whole window. The contract requires that: a sparse array would let a caller draw a
// continuous chart straight across a gap in activity, reading quiet as busy.
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
// A requested width that would produce more than maxTimelineBuckets is coarsened
// rather than rejected, and the width actually used is what the caller is told — a
// rejection would leave a caller who asked for 1m over a year with no timeline at all,
// when a coarser one answers the question they were asking.
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
		// Nothing requested: start from a width that puts the window in a readable
		// number of buckets, then let the cap below coarsen it if need be.
		width = window / 60
		if width < time.Minute {
			width = time.Minute
		}
	}

	for window/width > maxTimelineBuckets {
		next := coarsenInterval(width)
		if next <= width {
			// Already at the coarsest unit; widen by whole weeks until it fits.
			width += 7 * 24 * time.Hour
			continue
		}
		width = next
	}

	return formatTimelineInterval(width), nil
}

// parseTimelineInterval reads the contract's <count><unit> notation. An empty string
// is not an error: it means the adapter chooses.
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

// coarsenInterval steps up to the next unit, returning the input unchanged once there
// is no coarser one.
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

// formatTimelineInterval renders a duration back into the contract's notation, using
// the coarsest unit it divides evenly into.
//
// OpenSearch's fixed_interval accepts no unit above d, so weeks are rendered as their
// day count. The value reported to the caller is the one actually used either way.
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
//
// The named filter's own selections are dropped from the query, which is what keeps a
// picker offering the alternatives to what is already selected rather than only the
// selection itself.
func (qb *QueryBuilder) BuildAuditFilterValuesQuery(
	params AuditLogsQueryParams, field string, valueSearch string, maxValues int,
) map[string]interface{} {
	if maxValues <= 0 {
		maxValues = 100
	}

	terms := map[string]interface{}{
		"field": field,
		"size":  maxValues,
		// Busiest first, then by value, so a truncated list is the useful end of it.
		"order": []map[string]string{
			{"_count": "desc"},
			{"_key": "asc"},
		},
	}
	if include, ok := valueSearchRegex(valueSearch); ok {
		terms["include"] = include
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
				"cardinality": map[string]interface{}{
					"field": field,
				},
			},
		},
	}
}

// valueSearchRegex turns a case-insensitive substring search into the anchored Lucene
// regex a terms aggregation include takes.
//
// The regex engine has no (?i) flag, so each cased letter is expanded into a character
// class. Matching on a lowercase normalizer sub-field instead would return lowercased
// values, and the contract requires a value to come back exactly as it would be sent
// back as a filter.
//
// The expansion is roughly four times the input and the engine rejects anything over
// index.max_regex_length, so an over-long search returns false and is applied in Go
// after the fact instead.
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

// ParseAuditFilterValues reads the values aggregation back out of a search response.
func ParseAuditFilterValues(aggregations json.RawMessage) ([]AuditFilterValue, int64, bool, error) {
	if len(aggregations) == 0 {
		return nil, 0, false, nil
	}

	var parsed struct {
		Values struct {
			Buckets []struct {
				Key      string `json:"key"`
				DocCount int64  `json:"doc_count"`
			} `json:"buckets"`
			SumOtherDocCount int64 `json:"sum_other_doc_count"`
		} `json:"values"`
		TotalValues struct {
			Value int64 `json:"value"`
		} `json:"total_values"`
	}
	if err := json.Unmarshal(aggregations, &parsed); err != nil {
		return nil, 0, false, fmt.Errorf("failed to parse filter value aggregation: %w", err)
	}

	values := make([]AuditFilterValue, 0, len(parsed.Values.Buckets))
	for _, bucket := range parsed.Values.Buckets {
		// A value the field does not carry has no filter that would select it, so an
		// empty key is not offered as a choice.
		if bucket.Key == "" {
			continue
		}
		values = append(values, AuditFilterValue{Value: bucket.Key, Count: bucket.DocCount})
	}

	// cardinality is approximate above a threshold it does not report crossing, so the
	// count is labelled a lower bound whenever it could have been estimated. Claiming
	// an estimate is exact is the one thing the contract rules out.
	exact := parsed.TotalValues.Value <= int64(len(values)) && parsed.Values.SumOtherDocCount == 0

	return values, parsed.TotalValues.Value, exact, nil
}

// ParseAuditTimeline reads the timeline aggregation back out of a search response.
// Returns nil when the response carries none, which is a different answer from a
// timeline reporting no activity.
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
