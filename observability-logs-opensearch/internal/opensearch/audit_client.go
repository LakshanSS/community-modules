// Copyright 2026 The OpenChoreo Authors
// SPDX-License-Identifier: Apache-2.0

package opensearch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/opensearch-project/opensearch-go/v4/opensearchapi"
)

// ErrPITExpired reports that a point-in-time no longer exists: it lapsed, or the
// indices it was opened against have rolled or been deleted by retention.
//
// It is distinguished from an ordinary search failure because the caller's remedy
// differs - restart the query from the first page - and because the contract gives it
// its own status. Answering an empty page instead would read as the end of the trail.
var ErrPITExpired = errors.New("point-in-time has expired")

// CreatePIT opens a point-in-time over the given indices.
//
// Opening it against a wildcard resolves the concrete indices once, here, which is
// what stops a daily index created mid-scroll from shifting a page boundary.
func (c *Client) CreatePIT(ctx context.Context, indices []string, keepAlive time.Duration) (string, error) {
	resp, err := c.client.PointInTime.Create(ctx, opensearchapi.PointInTimeCreateReq{
		Indices: indices,
		Params: opensearchapi.PointInTimeCreateParams{
			KeepAlive: keepAlive,
		},
	})
	if err != nil {
		c.logger.Error("Failed to create point-in-time", "indices", indices, "error", err)
		return "", fmt.Errorf("failed to create point-in-time: %w", err)
	}
	return resp.PitID, nil
}

// DeletePIT releases a point-in-time.
//
// Failure is logged rather than returned: the caller has already answered, the PIT
// expires on its own, and turning a cleanup failure into a query failure would fail a
// request that actually succeeded.
func (c *Client) DeletePIT(ctx context.Context, pitID string) {
	if pitID == "" {
		return
	}
	if _, err := c.client.PointInTime.Delete(ctx, opensearchapi.PointInTimeDeleteReq{
		PitID: []string{pitID},
	}); err != nil {
		c.logger.Warn("Failed to delete point-in-time", "error", err)
	}
}

// SearchWithPIT runs a search against a point-in-time rather than a named index set.
//
// The pit and search_after clauses go in the body and no index is named, which is what
// the point-in-time API requires: the PIT already carries the indices.
func (c *Client) SearchWithPIT(
	ctx context.Context, query map[string]interface{}, cursor AuditCursor, keepAlive time.Duration,
) (*SearchResponse, error) {
	body := make(map[string]interface{}, len(query)+2)
	for k, v := range query {
		body[k] = v
	}
	body["pit"] = map[string]interface{}{
		"id": cursor.PITID,
		// Each access extends the lifetime, so a caller paging steadily keeps its
		// PIT alive without having to say so.
		"keep_alive": formatKeepAlive(keepAlive),
	}
	if len(cursor.SortAfter) > 0 {
		body["search_after"] = cursor.SortAfter
	}

	c.logger.Debug("Executing point-in-time search")

	// Issued as a raw request rather than through the typed Search call: the
	// client's SearchResp does not carry pit_id, and a PIT search must continue
	// against the id the cluster echoes back rather than the one that was sent.
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to encode search body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "/_search", bytes.NewReader(encoded))
	if err != nil {
		return nil, fmt.Errorf("failed to create search request: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")

	res, err := c.client.Client.Perform(req)
	if err != nil {
		c.logger.Error("Point-in-time search failed", "error", err)
		return nil, fmt.Errorf("point-in-time search failed: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(res.Body)
		if isPITExpiredResponse(res.StatusCode, payload) {
			return nil, ErrPITExpired
		}
		return nil, fmt.Errorf("point-in-time search failed with status %d: %s", res.StatusCode, payload)
	}

	response, err := parseSearchResponse(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse point-in-time search response: %w", err)
	}

	return response, nil
}

// formatKeepAlive renders a duration the way OpenSearch's keep_alive takes it.
func formatKeepAlive(d time.Duration) string {
	if d <= 0 {
		d = 5 * time.Minute
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

// isPITExpiredResponse reports whether a failed search failed because its
// point-in-time is gone, rather than for any other reason.
//
// OpenSearch reports it as a search_context_missing_exception inside the error body.
// The exception name is the stable part; the surrounding prose is not, so this matches
// on the name alone. A 404 carrying it is the documented shape, but the status has
// varied by version, so the body is what decides.
func isPITExpiredResponse(statusCode int, body []byte) bool {
	if statusCode < http.StatusBadRequest {
		return false
	}
	msg := strings.ToLower(string(body))
	return strings.Contains(msg, "search_context_missing_exception") ||
		strings.Contains(msg, "no search context found")
}
