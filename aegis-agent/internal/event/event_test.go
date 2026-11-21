package event

import (
	"encoding/json"
	"regexp"
	"testing"
	"time"
)

func TestNewIDIsUUIDShapedAndUnique(t *testing.T) {
	pattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	first, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if !pattern.MatchString(first) || !pattern.MatchString(second) {
		t.Fatalf("ID non UUIDv4: %q %q", first, second)
	}
	if first == second {
		t.Fatal("ID duplicato")
	}
}

func TestEventValidateAndJSON(t *testing.T) {
	ev := Event{
		AgentID:       "agent-1",
		Timestamp:     time.Now().UTC(),
		EventType:     EventTypeMetricsReport,
		SchemaVersion: SchemaVersion,
		CPUUsage:      12.5,
	}
	if err := ev.Validate(); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Event
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.AgentID != ev.AgentID || decoded.EventType != ev.EventType {
		t.Fatalf("round-trip = %+v", decoded)
	}
}

func TestEventValidateRejectsMissingRequiredFields(t *testing.T) {
	cases := []Event{
		{Timestamp: time.Now(), EventType: "X"},
		{AgentID: "a", Timestamp: time.Now()},
		{AgentID: "a", EventType: "X"},
		{AgentID: "a", Timestamp: time.Now(), EventType: "X", SchemaVersion: 1},
	}
	for i, ev := range cases {
		if err := ev.Validate(); err == nil {
			t.Fatalf("caso %d accettato", i)
		}
	}
}
