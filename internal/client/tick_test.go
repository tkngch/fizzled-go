package client_test

import (
	"testing"
	"time"

	"github.com/tkngch/fizzled-go/internal/client"
	fizzledv1 "github.com/tkngch/fizzled-go/internal/gen/fizzled/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

// TestTickJSONMatchesTheDocumentedShapes pins the bytes of every tick against
// the shapes the README's CLI section documents. A countdown is too slow for a
// test to reach its completion tick, so the encoding is exercised here on ticks
// built by hand rather than only through a stream.
func TestTickJSONMatchesTheDocumentedShapes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		tick     *fizzledv1.Tick
		expected string
	}{
		{
			name:     "progress: zero elapsed",
			tick:     progressTick(0, 5),
			expected: `{"progress":{"elapsed":"0s","remaining":5}}`,
		},
		{
			name:     "progress: zero remaining",
			tick:     progressTick(12300*time.Millisecond, 0),
			expected: `{"progress":{"elapsed":"12.300s","remaining":0}}`,
		},
		{
			name: "stopped",
			tick: &fizzledv1.Tick{
				Kind: &fizzledv1.Tick_Stopped{Stopped: &fizzledv1.Stopped{}},
			},
			expected: `{"stopped":{}}`,
		},
		{
			name: "failure",
			tick: &fizzledv1.Tick{
				Kind: &fizzledv1.Tick_Failure{
					Failure: &fizzledv1.Failure{Message: "unexpected error"},
				},
			},
			expected: `{"failure":{"message":"unexpected error"}}`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			encoded, err := client.TickJSON(testCase.tick)
			if err != nil {
				t.Fatalf("unexpected error from TickJSON(): %v", err)
			}

			if string(encoded) != testCase.expected {
				t.Errorf("expected [%s], got [%s]", testCase.expected, encoded)
			}
		})
	}
}

// progressTick is a progress tick carrying elapsed and remaining.
func progressTick(elapsed time.Duration, remaining int32) *fizzledv1.Tick {
	return &fizzledv1.Tick{
		Kind: &fizzledv1.Tick_Progress{
			Progress: &fizzledv1.Progress{
				Elapsed:   durationpb.New(elapsed),
				Remaining: remaining,
			},
		},
	}
}
