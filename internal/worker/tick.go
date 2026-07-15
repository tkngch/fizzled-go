package worker

import (
	"time"
)

// Tick is emitted by Job.
type Tick interface {
	// IsTerminal indicates whether the tick is terminal and no tick is expected
	// to follow.
	IsTerminal() bool

	isTick()
}

// Progress is a valid tick with the elapsed time and the remaining count.
type Progress struct {
	Elapsed   time.Duration
	Remaining int
}

// IsTerminal returns true when the job completed without an error and the tick
// is the last tick.
func (p Progress) IsTerminal() bool {
	return p.Remaining == 0
}

func (Progress) isTick() {}

// Stopped is a terminal tick emitted on job cancelation. It carries the
// cancelation cause but it is not an error itself.
type Stopped struct {
	Cause error // context.Canceled or context.DeadlineExceeded
}

// IsTerminal returns true if it is stopped.
func (Stopped) IsTerminal() bool {
	return true
}

func (Stopped) isTick() {}

// PanicError is a terminal tick emitted on panic.
type PanicError struct {
	Err error
}

// IsTerminal returns true if it is a failure.
func (PanicError) IsTerminal() bool {
	return true
}

// Error returns an error message.
func (f PanicError) Error() string {
	if f.Err == nil {
		return "job failure without an error"
	}

	return "job failure: " + f.Err.Error()
}

// Unwrap returns the wrapped error, so errors.Is and errors.As can match it.
func (f PanicError) Unwrap() error {
	return f.Err
}

func (PanicError) isTick() {}
