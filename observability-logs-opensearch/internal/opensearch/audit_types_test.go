// Copyright 2026 The OpenChoreo Authors
// SPDX-License-Identifier: Apache-2.0

package opensearch

import "testing"

// completeAuditSource carries every field the contract requires.
func completeAuditSource() map[string]interface{} {
	return map[string]interface{}{
		"schema_version": "1.0",
		"event_id":       "0192f1a0-0000-7000-8000-000000000001",
		"event_time":     "2026-09-01T10:00:00Z",
		"actor": map[string]interface{}{
			"type": "user",
			"id":   "user-1",
		},
		"action":   "create_project",
		"category": "management",
		"result":   "success",
	}
}

func TestParseAuditRecord_ReadsACompleteRecord(t *testing.T) {
	record, err := ParseAuditRecord(Hit{ID: "doc-1", Source: completeAuditSource()})
	if err != nil {
		t.Fatalf("ParseAuditRecord() error = %v", err)
	}
	if record.EventID != "0192f1a0-0000-7000-8000-000000000001" {
		t.Errorf("eventID = %q", record.EventID)
	}
	if record.Actor.ID != "user-1" || record.Actor.Type != "user" {
		t.Errorf("actor = %+v", record.Actor)
	}
}

// A blank in any of these would go on the wire as a real reading.
func TestParseAuditRecord_RejectsAMissingIdentityField(t *testing.T) {
	for _, field := range []string{
		"schema_version", "event_id", "event_time", "actor", "result",
	} {
		t.Run(field, func(t *testing.T) {
			source := completeAuditSource()
			delete(source, field)

			if _, err := ParseAuditRecord(Hit{ID: "doc-1", Source: source}); err == nil {
				t.Errorf("expected an error for a document with no %s, got nil", field)
			}
		})
	}
}

// A request rejected before routing resolves an action is recorded with both empty.
func TestParseAuditRecord_KeepsARecordWithNoResolvedAction(t *testing.T) {
	source := completeAuditSource()
	source["action"] = ""
	source["category"] = ""
	source["result"] = "unauthenticated"
	source["actor"] = map[string]interface{}{"type": "anonymous", "id": "anonymous"}

	record, err := ParseAuditRecord(Hit{ID: "doc-1", Source: source})
	if err != nil {
		t.Fatalf("ParseAuditRecord() error = %v, want the record kept", err)
	}
	if record.Result != "unauthenticated" || record.Actor.ID != "anonymous" {
		t.Errorf("record = %+v, want the anonymous rejection intact", record)
	}
}
