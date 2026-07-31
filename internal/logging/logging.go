package logging

import "log/slog"

// OrDiscard is logger, or a logger that discards everything when logger is nil.
func OrDiscard(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return slog.New(slog.DiscardHandler)
	}

	return logger
}
