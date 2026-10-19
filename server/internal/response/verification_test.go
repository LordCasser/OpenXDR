package response

import (
	"errors"
	"github.com/google/uuid"
	"strings"
	"testing"
)

func TestVerificationRequiresEvidence(t *testing.T) {
	for _, outcome := range []string{"effective", "ineffective", "inconclusive"} {
		in := VerificationInput{Outcome: outcome, Expected: "预期", Observed: "观察"}
		if err := in.validate(); (err == nil) != (outcome == "inconclusive") {
			t.Fatalf("无证据结论 %s: %v", outcome, err)
		}
		in.EventIDs = []uuid.UUID{uuid.New()}
		if err := in.validate(); err != nil {
			t.Fatal(err)
		}
	}
	id := uuid.New()
	for _, in := range []VerificationInput{
		{Outcome: "succeeded", Expected: "预期", Observed: "观察"},
		{Outcome: "inconclusive", Expected: " ", Observed: "观察"},
		{Outcome: "inconclusive", Expected: "预期", Observed: strings.Repeat("x", 4001)},
		{Outcome: "inconclusive", Expected: "预期", Observed: "\x00"},
		{Outcome: "inconclusive", Expected: "预期", Observed: "观察", EventIDs: []uuid.UUID{uuid.Nil}},
		{Outcome: "inconclusive", Expected: "预期", Observed: "观察", EventIDs: []uuid.UUID{id, id}},
		{Outcome: "inconclusive", Expected: "预期", Observed: "观察", EventIDs: make([]uuid.UUID, 21)},
	} {
		if err := in.validate(); !errors.Is(err, ErrVerificationInput) {
			t.Fatalf("接受无效输入: %+v", in)
		}
	}
}
