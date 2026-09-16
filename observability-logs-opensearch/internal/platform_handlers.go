// Copyright 2026 The OpenChoreo Authors
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/openchoreo/community-modules/observability-logs-opensearch/internal/api/gen"
	"github.com/openchoreo/community-modules/observability-logs-opensearch/internal/opensearch"
)

// QueryPlatformLogs implements POST /api/v1alpha1/platform-logs/query.
//
// Platform logs share the container-logs-* index with workload logs; what distinguishes
// them is the filter, not the store. There is no scope to resolve here - the observer has
// already decided who may ask - so this maps the request onto a query and back.
func (h *LogsHandler) QueryPlatformLogs(
	ctx context.Context, request gen.QueryPlatformLogsRequestObject,
) (gen.QueryPlatformLogsResponseObject, error) {
	if request.Body == nil {
		return gen.QueryPlatformLogs400JSONResponse{
			Title:   ptr(gen.BadRequest),
			Message: ptr("request body is required"),
		}, nil
	}
	params := platformQueryParams(request.Body)
	startTime, endTime := params.StartTime, params.EndTime

	query := h.queryBuilder.BuildPlatformLogsQuery(params)

	indices, err := h.queryBuilder.GenerateIndices(startTime, endTime)
	if err != nil {
		h.logger.Error("Failed to generate indices",
			slog.String("function", "QueryPlatformLogs"),
			slog.Any("error", err),
		)
		return gen.QueryPlatformLogs500JSONResponse{
			Title:   ptr(gen.InternalServerError),
			Message: ptr("internal server error"),
		}, nil
	}

	result, err := h.osClient.Search(ctx, indices, query)
	if err != nil {
		h.logger.Error("Failed to query platform logs",
			slog.String("function", "QueryPlatformLogs"),
			slog.Any("error", err),
		)
		return gen.QueryPlatformLogs500JSONResponse{
			Title:   ptr(gen.InternalServerError),
			Message: ptr("internal server error"),
		}, nil
	}

	logs := make([]gen.PlatformLog, 0, len(result.Hits.Hits))
	for _, hit := range result.Hits.Hits {
		// timestamp and log are required by the contract, and this module owns those
		// guarantees. A document reaching here should satisfy both - the query
		// range-filters on @timestamp, and the index holds container logs - so a parse
		// failure means the document is malformed. Emitting it would put
		// 0001-01-01T00:00:00Z on the wire as a real reading, or a blank line that was
		// never logged, so skip it and say which document and why.
		entry, err := opensearch.ParsePlatformLogEntry(hit)
		if err != nil {
			h.logger.Warn("skipping malformed log document", "docId", hit.ID, "error", err)
			continue
		}

		log := gen.PlatformLog{
			Timestamp:       entry.Timestamp,
			Log:             entry.Log,
			Level:           optional(entry.LogLevel),
			ClusterInstance: optional(entry.ClusterInstance),
			NamespaceName:   optional(entry.NamespaceName),
			PodName:         optional(entry.PodName),
			ContainerName:   optional(entry.ContainerName),
			PodIp:           optional(entry.PodIP),
			NodeName:        optional(entry.NodeName),
			ContainerImage:  optional(entry.ContainerImage),
		}
		if len(entry.Labels) > 0 {
			labels := entry.Labels
			log.Labels = &labels
		}
		logs = append(logs, log)
	}

	return gen.QueryPlatformLogs200JSONResponse{
		Logs:   logs,
		Total:  result.Hits.Total.Value,
		TookMs: result.Took,
	}, nil
}

// QueryPlatformLogFilterValues implements POST /api/v1alpha1/platform-logs/filter-values.
//
// Answers "what can I pick next" for one filter: the distinct values it takes among the
// records the rest of the query already selects. The listed filter's own selections are
// dropped first - counting them would offer back only what is already picked, so a choice
// could never be widened once made.
func (h *LogsHandler) QueryPlatformLogFilterValues(
	ctx context.Context, request gen.QueryPlatformLogFilterValuesRequestObject,
) (gen.QueryPlatformLogFilterValuesResponseObject, error) {
	if request.Body == nil {
		return gen.QueryPlatformLogFilterValues400JSONResponse{
			Title:   ptr(gen.BadRequest),
			Message: ptr("request body is required"),
		}, nil
	}
	body := request.Body

	filter := string(body.Filter)
	field, ok := opensearch.PlatformFilterField(filter)
	if !ok {
		// The contract's enum already excludes this, but the adapter decides what it can
		// list, so say which filter was refused rather than returning an empty list that
		// reads as "no values".
		return gen.QueryPlatformLogFilterValues400JSONResponse{
			Title:   ptr(gen.BadRequest),
			Message: ptr(fmt.Sprintf("filter %q cannot be listed", filter)),
		}, nil
	}

	maxValues := opensearch.DefaultMaxFilterValues
	if body.MaxValues != nil {
		maxValues = *body.MaxValues
	}
	if maxValues < 1 {
		maxValues = 1
	}
	if maxValues > opensearch.MaxMaxFilterValues {
		maxValues = opensearch.MaxMaxFilterValues
	}

	valueSearch := ""
	if body.ValueSearch != nil {
		valueSearch = *body.ValueSearch
	}

	// limit and sortOrder page and order records; this returns none, so they are ignored
	// rather than rejected, as the contract requires.
	params := platformQueryParams(&body.Query)
	params = opensearch.ClearFilterSelections(params, filter)

	query := h.queryBuilder.BuildPlatformLogFilterValuesQuery(params, field, valueSearch, maxValues)

	indices, err := h.queryBuilder.GenerateIndices(params.StartTime, params.EndTime)
	if err != nil {
		h.logger.Error("Failed to generate indices",
			slog.String("function", "QueryPlatformLogFilterValues"),
			slog.Any("error", err),
		)
		return gen.QueryPlatformLogFilterValues500JSONResponse{
			Title:   ptr(gen.InternalServerError),
			Message: ptr("internal server error"),
		}, nil
	}

	result, err := h.osClient.Search(ctx, indices, query)
	if err != nil {
		h.logger.Error("Failed to query platform log filter values",
			slog.String("function", "QueryPlatformLogFilterValues"),
			slog.String("filter", filter),
			slog.Any("error", err),
		)
		return gen.QueryPlatformLogFilterValues500JSONResponse{
			Title:   ptr(gen.InternalServerError),
			Message: ptr("internal server error"),
		}, nil
	}

	parsed, err := opensearch.ParsePlatformLogFilterValues(result.Aggregations, maxValues)
	if err != nil {
		h.logger.Error("Failed to parse filter value aggregation",
			slog.String("function", "QueryPlatformLogFilterValues"),
			slog.String("filter", filter),
			slog.Any("error", err),
		)
		return gen.QueryPlatformLogFilterValues500JSONResponse{
			Title:   ptr(gen.InternalServerError),
			Message: ptr("internal server error"),
		}, nil
	}

	values := make([]gen.PlatformLogFilterValue, 0, len(parsed.Values))
	for _, v := range parsed.Values {
		values = append(values, gen.PlatformLogFilterValue{Value: v.Value, Count: v.Count})
	}

	return gen.QueryPlatformLogFilterValues200JSONResponse{
		Filter:      filter,
		Values:      values,
		TotalValues: parsed.TotalValues,
		TookMs:      result.Took,
	}, nil
}

// derefSlice returns the pointed-to slice, or nil. An absent multi-value filter and an
// empty one mean the same thing here: not a filter.
func derefSlice(v *[]string) []string {
	if v == nil {
		return nil
	}
	return *v
}

// optional returns a pointer to s, or nil when s is empty, so an unknown field is omitted
// from the response rather than serialised as "".
func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// platformQueryParams maps a platform logs query request onto the query builder's
// parameters. Both the record query and the filter-values query take the same request
// shape, so the mapping lives here rather than in each handler.
func platformQueryParams(body *gen.PlatformLogsQueryRequest) opensearch.PlatformLogsQueryParams {
	params := opensearch.PlatformLogsQueryParams{
		StartTime:        body.StartTime.Format(time.RFC3339),
		EndTime:          body.EndTime.Format(time.RFC3339),
		ClusterInstances: derefSlice(body.ClusterInstance),
		Namespaces:       derefSlice(body.Namespace),
		PodNames:         derefSlice(body.PodName),
		ContainerNames:   derefSlice(body.ContainerName),
	}
	if body.Labels != nil {
		params.Labels = *body.Labels
	}
	if body.Limit != nil {
		params.Limit = *body.Limit
	}
	if body.SortOrder != nil {
		params.SortOrder = string(*body.SortOrder)
	}
	if body.SearchPhrase != nil {
		params.SearchPhrase = *body.SearchPhrase
	}
	if body.LogLevels != nil {
		levels := make([]string, len(*body.LogLevels))
		for i, l := range *body.LogLevels {
			levels[i] = string(l)
		}
		params.LogLevels = levels
	}
	return params
}
