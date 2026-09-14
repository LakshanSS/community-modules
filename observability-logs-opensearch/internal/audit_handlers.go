// Copyright 2026 The OpenChoreo Authors
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/openchoreo/community-modules/observability-logs-opensearch/internal/api/gen"
	"github.com/openchoreo/community-modules/observability-logs-opensearch/internal/opensearch"
)

// auditFilterFields maps a filter name from the contract onto the field it is stored
// at. The two differ only where the record's shape and the index's differ, which is
// why the exceptions are worth naming rather than deriving.
var auditFilterFields = map[gen.AuditLogFilterValuesRequestFilter]string{
	"actor.id":         "actor.id",
	"actor.type":       "actor.type",
	"actor.issuer":     "actor.issuer",
	"actor.session_id": "actor.session_id",
	// The claim key varies by subject kind, so the picker reads the copy the index
	// template collects every claim's values into.
	"actor.entitlements":   opensearch.AuditEntitlementValuesField,
	"resource.type":        "resource.type",
	"resource.namespace":   "resource.namespace",
	"resource.environment": "resource.environment",
	"resource.project":     "resource.project",
	"resource.component":   "resource.component",
	"resource.name":        "resource.name",
	"action":               "action",
	"category":             "category",
	"result":               "result",
	"producer":             "producer",
	"surface":              "surface",
	"operation_id":         "operation_id",
	"source_ip":            "source_ip",
	"user_agent":           "user_agent",
}

// QueryAuditLogs implements POST /api/v1alpha1/audit-logs/query.
func (h *LogsHandler) QueryAuditLogs(
	ctx context.Context, request gen.QueryAuditLogsRequestObject,
) (gen.QueryAuditLogsResponseObject, error) {
	if request.Body == nil {
		return gen.QueryAuditLogs400JSONResponse{
			Title:   ptr(gen.BadRequest),
			Message: ptr("request body is required"),
		}, nil
	}
	body := request.Body

	if !body.EndTime.After(body.StartTime) {
		return gen.QueryAuditLogs400JSONResponse{
			Title:   ptr(gen.BadRequest),
			Message: ptr("endTime must be after startTime"),
		}, nil
	}

	params := toAuditLogsQueryParams(body)
	query := h.auditQueryBuilder.BuildAuditLogsQuery(params)

	// The timeline covers the whole window, not just the page, so it is computed
	// once on the first request and omitted from every continuation.
	timelineInterval := ""
	if body.IncludeTimeline != nil && *body.IncludeTimeline && body.Cursor == nil {
		requested := ""
		if body.TimelineInterval != nil {
			requested = *body.TimelineInterval
		}
		resolved, err := opensearch.ResolveTimelineInterval(requested, body.StartTime, body.EndTime)
		if err != nil {
			return gen.QueryAuditLogs400JSONResponse{
				Title:   ptr(gen.BadRequest),
				Message: ptr(err.Error()),
			}, nil
		}
		timelineInterval = resolved
		query["aggs"] = opensearch.BuildAuditTimelineAgg(
			timelineInterval, params.StartTime, params.EndTime)
	}

	cursor, err := h.resolveAuditCursor(ctx, body)
	if err != nil {
		h.logger.Error("Failed to resolve audit cursor",
			slog.String("function", "QueryAuditLogs"),
			slog.Any("error", err),
		)
		return gen.QueryAuditLogs500JSONResponse{
			Title:   ptr(gen.InternalServerError),
			Message: ptr("internal server error"),
		}, nil
	}

	result, err := h.osClient.SearchWithPIT(ctx, query, cursor, h.auditCursorKeepAlive)
	if err != nil {
		// An expired cursor is the caller's to act on - restart from the first page -
		// so it is reported as its own status. Answering an empty page would read as
		// the end of the trail, which is the one answer that must not be invented.
		if errors.Is(err, opensearch.ErrPITExpired) {
			return gen.QueryAuditLogs410JSONResponse{
				Title:   ptr(gen.Gone),
				Message: ptr("audit logs cursor has expired; restart the query"),
			}, nil
		}
		h.logger.Error("Failed to query audit logs",
			slog.String("function", "QueryAuditLogs"),
			slog.Any("error", err),
		)
		return gen.QueryAuditLogs500JSONResponse{
			Title:   ptr(gen.InternalServerError),
			Message: ptr("internal server error"),
		}, nil
	}

	records := make([]gen.AuditLogRecord, 0, len(result.Hits.Hits))
	for _, hit := range result.Hits.Hits {
		// A document that does not parse is not emitted as a zero-valued record: a
		// blank actor at the epoch reads as a real finding of "nobody, at no time",
		// which is worse than saying which document is unreadable.
		record, err := opensearch.ParseAuditRecord(hit)
		if err != nil {
			h.logger.Warn("Skipping malformed audit document",
				slog.String("docId", hit.ID),
				slog.Any("error", err),
			)
			continue
		}
		records = append(records, toGenAuditLogRecord(record))
	}

	response := gen.AuditLogsResponse{
		Records:       records,
		Total:         int64(result.Hits.Total.Value),
		TotalRelation: toTotalRelation(result.Hits.Total.Relation),
		TookMs:        int64(result.Took),
	}

	// A next cursor is minted only for a full page. Offering one on a short page
	// would make the caller fetch an empty page to discover the end.
	if len(result.Hits.Hits) > 0 && len(result.Hits.Hits) == params.Limit {
		last := result.Hits.Hits[len(result.Hits.Hits)-1]
		if len(last.Sort) > 0 {
			pitID := result.PitID
			if pitID == "" {
				pitID = cursor.PITID
			}
			next, err := opensearch.AuditCursor{
				PITID:     pitID,
				SortAfter: last.Sort,
				SortOrder: params.SortOrder,
			}.Encode()
			if err != nil {
				h.logger.Error("Failed to encode audit cursor",
					slog.String("function", "QueryAuditLogs"),
					slog.Any("error", err),
				)
				return gen.QueryAuditLogs500JSONResponse{
					Title:   ptr(gen.InternalServerError),
					Message: ptr("internal server error"),
				}, nil
			}
			response.NextCursor = &next
		}
	}

	if timelineInterval != "" {
		timeline, err := opensearch.ParseAuditTimeline(result.Aggregations, timelineInterval)
		if err != nil {
			// The records are already in hand and answering them is more useful than
			// failing the query, so the timeline is dropped and its absence says so.
			h.logger.Warn("Failed to parse audit timeline",
				slog.String("function", "QueryAuditLogs"),
				slog.Any("error", err),
			)
		} else if timeline != nil {
			response.Timeline = toGenAuditTimeline(timeline)
		}
	}

	return gen.QueryAuditLogs200JSONResponse(response), nil
}

// QueryAuditLogFilterValues implements POST /api/v1alpha1/audit-logs/filter-values.
func (h *LogsHandler) QueryAuditLogFilterValues(
	ctx context.Context, request gen.QueryAuditLogFilterValuesRequestObject,
) (gen.QueryAuditLogFilterValuesResponseObject, error) {
	if request.Body == nil {
		return gen.QueryAuditLogFilterValues400JSONResponse{
			Title:   ptr(gen.BadRequest),
			Message: ptr("request body is required"),
		}, nil
	}
	body := request.Body

	field, ok := auditFilterFields[body.Filter]
	if !ok {
		return gen.QueryAuditLogFilterValues400JSONResponse{
			Title:   ptr(gen.BadRequest),
			Message: ptr("unknown filter: " + string(body.Filter)),
		}, nil
	}

	if !body.Query.EndTime.After(body.Query.StartTime) {
		return gen.QueryAuditLogFilterValues400JSONResponse{
			Title:   ptr(gen.BadRequest),
			Message: ptr("query.endTime must be after query.startTime"),
		}, nil
	}

	// The named filter's own selections are dropped so the picker keeps offering the
	// alternatives to what is already selected, rather than only the selection.
	params := toAuditLogsQueryParams(&body.Query)
	clearAuditFilter(&params, body.Filter)

	valueSearch := ""
	if body.ValueSearch != nil {
		valueSearch = *body.ValueSearch
	}
	maxValues := 100
	if body.MaxValues != nil {
		maxValues = *body.MaxValues
	}

	query := h.auditQueryBuilder.BuildAuditFilterValuesQuery(params, field, valueSearch, maxValues)

	indices := []string{h.auditQueryBuilder.AuditIndexPattern()}
	result, err := h.osClient.Search(ctx, indices, query)
	if err != nil {
		h.logger.Error("Failed to query audit log filter values",
			slog.String("function", "QueryAuditLogFilterValues"),
			slog.String("filter", string(body.Filter)),
			slog.Any("error", err),
		)
		return gen.QueryAuditLogFilterValues500JSONResponse{
			Title:   ptr(gen.InternalServerError),
			Message: ptr("internal server error"),
		}, nil
	}

	values, totalValues, exact, err := opensearch.ParseAuditFilterValues(result.Aggregations)
	if err != nil {
		h.logger.Error("Failed to parse audit log filter values",
			slog.String("function", "QueryAuditLogFilterValues"),
			slog.Any("error", err),
		)
		return gen.QueryAuditLogFilterValues500JSONResponse{
			Title:   ptr(gen.InternalServerError),
			Message: ptr("internal server error"),
		}, nil
	}

	// A search too long to express as an aggregation regex was sent without one, so
	// it is applied here instead. Applying it twice is harmless.
	values = opensearch.FilterValuesBySearch(values, valueSearch)

	genValues := make([]gen.AuditLogFilterValue, 0, len(values))
	for _, v := range values {
		genValues = append(genValues, gen.AuditLogFilterValue{Value: v.Value, Count: v.Count})
	}

	relation := gen.AuditLogFilterValuesResponseTotalRelation("gte")
	if exact {
		relation = "eq"
	}

	return gen.QueryAuditLogFilterValues200JSONResponse{
		Filter:        string(body.Filter),
		Values:        genValues,
		TotalValues:   totalValues,
		TotalRelation: relation,
		TookMs:        int64(result.Took),
	}, nil
}

// resolveAuditCursor continues the page the caller sent, or opens a new point in time
// for a first page.
func (h *LogsHandler) resolveAuditCursor(
	ctx context.Context, body *gen.AuditLogsQueryRequest,
) (opensearch.AuditCursor, error) {
	if body.Cursor != nil && *body.Cursor != "" {
		return opensearch.DecodeAuditCursor(*body.Cursor)
	}

	pitID, err := h.osClient.CreatePIT(
		ctx,
		[]string{h.auditQueryBuilder.AuditIndexPattern()},
		h.auditCursorKeepAlive,
	)
	if err != nil {
		return opensearch.AuditCursor{}, err
	}
	return opensearch.AuditCursor{PITID: pitID}, nil
}

// toAuditLogsQueryParams maps the request onto the query params. The filter groups are
// nested the same way on both sides, so this stays a field-for-field copy - which is
// where a rename would otherwise go unnoticed.
func toAuditLogsQueryParams(body *gen.AuditLogsQueryRequest) opensearch.AuditLogsQueryParams {
	params := opensearch.AuditLogsQueryParams{
		StartTime:    body.StartTime.Format(time.RFC3339),
		EndTime:      body.EndTime.Format(time.RFC3339),
		Actions:      derefSlice(body.Action),
		Producers:    derefSlice(body.Producer),
		OperationIDs: derefSlice(body.OperationId),
		RequestIDs:   derefSlice(body.RequestId),
		EventIDs:     derefSlice(body.EventId),
		SourceIPs:    derefSlice(body.SourceIp),
		UserAgents:   derefSlice(body.UserAgent),
		Limit:        100,
		SortOrder:    "desc",
	}

	if body.Actor != nil {
		params.ActorIDs = derefSlice(body.Actor.Id)
		params.ActorTypes = derefSlice(body.Actor.Type)
		params.ActorIssuers = derefSlice(body.Actor.Issuer)
		params.ActorSessionIDs = derefSlice(body.Actor.SessionId)
		params.ActorEntitlements = derefSlice(body.Actor.Entitlements)
	}

	if body.Resource != nil {
		params.ResourceTypes = derefSlice(body.Resource.Type)
		params.ResourceNamespaces = derefSlice(body.Resource.Namespace)
		params.ResourceEnvironments = derefSlice(body.Resource.Environment)
		params.ResourceProjects = derefSlice(body.Resource.Project)
		params.ResourceComponents = derefSlice(body.Resource.Component)
		params.ResourceNames = derefSlice(body.Resource.Name)
	}

	// The closed enums carry generated types rather than plain strings, so each needs
	// its own conversion. The observer has already rejected unknown values by here.
	if body.Category != nil {
		for _, c := range *body.Category {
			params.Categories = append(params.Categories, string(c))
		}
	}
	if body.Result != nil {
		for _, r := range *body.Result {
			params.Results = append(params.Results, string(r))
		}
	}
	if body.Surface != nil {
		for _, s := range *body.Surface {
			params.Surfaces = append(params.Surfaces, string(s))
		}
	}

	if body.SearchPhrase != nil {
		params.SearchPhrase = *body.SearchPhrase
	}
	if body.Limit != nil && *body.Limit > 0 {
		params.Limit = *body.Limit
	}
	if body.SortOrder != nil {
		params.SortOrder = string(*body.SortOrder)
	}

	return params
}

// clearAuditFilter drops one filter's own selections, for the value picker.
func clearAuditFilter(
	params *opensearch.AuditLogsQueryParams, filter gen.AuditLogFilterValuesRequestFilter,
) {
	switch filter {
	case "actor.id":
		params.ActorIDs = nil
	case "actor.type":
		params.ActorTypes = nil
	case "actor.issuer":
		params.ActorIssuers = nil
	case "actor.session_id":
		params.ActorSessionIDs = nil
	case "actor.entitlements":
		params.ActorEntitlements = nil
	case "resource.type":
		params.ResourceTypes = nil
	case "resource.namespace":
		params.ResourceNamespaces = nil
	case "resource.environment":
		params.ResourceEnvironments = nil
	case "resource.project":
		params.ResourceProjects = nil
	case "resource.component":
		params.ResourceComponents = nil
	case "resource.name":
		params.ResourceNames = nil
	case "action":
		params.Actions = nil
	case "category":
		params.Categories = nil
	case "result":
		params.Results = nil
	case "producer":
		params.Producers = nil
	case "surface":
		params.Surfaces = nil
	case "operation_id":
		params.OperationIDs = nil
	case "source_ip":
		params.SourceIPs = nil
	case "user_agent":
		params.UserAgents = nil
	}
}

// toTotalRelation passes the backend's own count relation through.
//
// A count the backend stopped short of is reported as a lower bound rather than as an
// exact figure: an audit consumer reading a capped total as exact draws the wrong
// conclusion about how much happened.
func toTotalRelation(relation string) gen.AuditLogsResponseTotalRelation {
	if strings.EqualFold(relation, "eq") {
		return "eq"
	}
	return "gte"
}

func toGenAuditLogRecord(r opensearch.AuditRecord) gen.AuditLogRecord {
	record := gen.AuditLogRecord{
		SchemaVersion: r.SchemaVersion,
		EventId:       r.EventID,
		EventTime:     r.EventTime,
		Actor: gen.AuditLogActor{
			Type:      r.Actor.Type,
			Id:        r.Actor.ID,
			Issuer:    optional(r.Actor.Issuer),
			SessionId: optional(r.Actor.SessionID),
		},
		Action:      r.Action,
		Category:    r.Category,
		Result:      r.Result,
		RequestId:   optional(r.RequestID),
		SourceIp:    optional(r.SourceIP),
		UserAgent:   optional(r.UserAgent),
		Producer:    optional(r.Producer),
		Surface:     optional(r.Surface),
		OperationId: optional(r.OperationID),
		Log:         optional(r.Log),
	}

	if len(r.Actor.Entitlements) > 0 {
		entitlements := r.Actor.Entitlements
		record.Actor.Entitlements = &entitlements
	}
	if len(r.Metadata) > 0 {
		metadata := r.Metadata
		record.Metadata = &metadata
	}
	if r.HTTP != nil {
		record.Http = &gen.AuditLogHTTPInfo{
			Method: optional(r.HTTP.Method),
			Path:   optional(r.HTTP.Path),
		}
	}
	if r.Resource != nil {
		resource := gen.AuditLogResource{
			Type:        optional(r.Resource.Type),
			Namespace:   optional(r.Resource.Namespace),
			Environment: optional(r.Resource.Environment),
			Project:     optional(r.Resource.Project),
			Component:   optional(r.Resource.Component),
			Resource:    optional(r.Resource.Resource),
			Uid:         optional(r.Resource.UID),
			Name:        optional(r.Resource.Name),
		}
		if len(r.Resource.Metadata) > 0 {
			metadata := r.Resource.Metadata
			resource.Metadata = &metadata
		}
		record.Resource = &resource
	}

	collector := gen.AuditLogCollectorInfo{
		NamespaceName: optional(r.Kubernetes.NamespaceName),
		PodName:       optional(r.Kubernetes.PodName),
		ContainerName: optional(r.Kubernetes.ContainerName),
	}
	if collector != (gen.AuditLogCollectorInfo{}) {
		record.Collector = &collector
	}

	return record
}

func toGenAuditTimeline(t *opensearch.AuditTimeline) *gen.AuditLogTimeline {
	buckets := make([]gen.AuditLogTimelineBucket, 0, len(t.Buckets))
	for _, b := range t.Buckets {
		bucket := gen.AuditLogTimelineBucket{
			StartTime: b.StartTime,
			Total:     b.Total,
		}
		if len(b.Counts) > 0 {
			counts := b.Counts
			bucket.Counts = &counts
		}
		buckets = append(buckets, bucket)
	}
	return &gen.AuditLogTimeline{Interval: t.Interval, Buckets: buckets}
}
