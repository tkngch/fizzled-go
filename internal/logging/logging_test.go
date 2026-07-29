package logging_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/tkngch/fizzled-go/internal/logging"
)

func TestOrDiscard(t *testing.T) {
	t.Parallel()

	t.Run("hands back the logger it was given", func(t *testing.T) {
		t.Parallel()

		recorded := &bytes.Buffer{}
		logger := slog.New(slog.NewJSONHandler(recorded, nil))

		logging.OrDiscard(logger).Info("written")

		if recorded.Len() == 0 {
			t.Errorf("expected the caller's logger to be used, got nothing")
		}
	})

	t.Run("discards when given none", func(t *testing.T) {
		t.Parallel()

		// The point is that this neither panics nor reaches slog.Default: a
		// caller that passed nothing asked for nothing.
		logging.OrDiscard(nil).Info("dropped")
	})
}
