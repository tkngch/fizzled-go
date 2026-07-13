package worker

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"math/rand/v2"
	"sync"
	"time"
)

// JobID identifies a job.
type JobID string

// Job is a stochastic countdown job.
type Job struct {
	id     JobID
	status Status

	ticks            []Tick
	meanTickInterval time.Duration

	cancel context.CancelFunc

	changed  chan struct{}
	finished chan struct{}

	// mutex guards status and ticks together, so a terminal transition and
	// its sentinel append happen atomically as one unit.
	mutex sync.Mutex
}

// MaxCount is the largest count a job accepts.
const MaxCount = 100

var (
	// ErrInvalidCount indicates that a count is invalid.
	ErrInvalidCount = errors.New("invalid count; expected positive count below the maximum")

	// ErrInvalidMeanInterval indicates that a mean interval is invalid.
	ErrInvalidMeanInterval = errors.New("invalid mean interval; expected positive duration")

	// ErrJobPanic indicates that the job encountered a panic.
	ErrJobPanic = errors.New("job panic")
)

// NewJob starts a job with RUNNING status. It returns an error when count is
// zero or negative or very large, or when the mean tick interval is zero or
// negative.
func NewJob(
	ctx context.Context,
	jobID JobID,
	count int,
	meanTickInterval time.Duration,
) (*Job, error) {
	if count <= 0 || count > MaxCount {
		return nil, fmt.Errorf("new-job [count %d]: %w", count, ErrInvalidCount)
	}

	if meanTickInterval <= 0 {
		return nil, fmt.Errorf(
			"new-job [mean interval %s]: %w",
			meanTickInterval,
			ErrInvalidMeanInterval,
		)
	}

	jobCtx, jobCancel := context.WithCancel(ctx)
	job := &Job{
		id:     jobID,
		status: StatusRunning,
		// +1 to the capacity accounts for the final zero tick
		ticks:            make([]Tick, 0, count+1),
		meanTickInterval: meanTickInterval,
		cancel:           jobCancel,
		changed:          make(chan struct{}),
		finished:         make(chan struct{}),
		mutex:            sync.Mutex{},
	}

	go job.countdown(jobCtx, count)

	return job, nil
}

// ID returns the job's ID.
func (j *Job) ID() JobID {
	return j.id
}

// Status returns the job's current status.
func (j *Job) Status() Status {
	j.mutex.Lock()
	defer j.mutex.Unlock()

	return j.status
}

// Stop requests cancellation of the job, blocks until the job finishes, and
// reports whether that job actually stopped. It returns false if the job had
// already completed or failed. Concurrent calls all observe the same results,
// regardless of whether the call drives the cancellation.
func (j *Job) Stop() bool {
	j.cancel()
	<-j.finished

	return j.Status() == StatusStopped
}

// Ticks iterates over the job's ticks: the full sequence from the start, then
// live ticks, until a terminal tick, ctx cancellation, or the caller stops the
// range. Multiple goroutines may read concurrently; each gets the full
// sequence. A terminal tick ends iteration whether the job completed or
// failed.
func (j *Job) Ticks(ctx context.Context) iter.Seq[Tick] {
	return func(yield func(Tick) bool) {
		cursor := 0

		for {
			j.mutex.Lock()
			// Reading newTicks after unlocking is safe: appended Tick values
			// are never mutated, a reader only reads indices below the captured
			// length while the writer only appends at or after it, and the
			// count+1 preallocation keeps the backing array from moving.
			newTicks := j.ticks[cursor:]
			cursor = len(j.ticks)
			wait := j.changed
			j.mutex.Unlock()

			for _, tick := range newTicks {
				if !yield(tick) {
					return
				}

				if tick.IsTerminal() {
					return
				}
			}

			// Drained a batch; loop to re-check before blocking.
			if len(newTicks) > 0 {
				continue
			}

			select {
			case <-wait:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (j *Job) countdown(ctx context.Context, count int) {
	// Release the job's context on exit so a finished job does not linger on.
	defer j.cancel()
	defer close(j.finished)

	defer func() {
		switch recovered := recover().(type) {
		case nil:
			return
		case error:
			j.finish(StatusFailed, PanicError{fmt.Errorf("%w: %w", recovered, ErrJobPanic)})
		default:
			j.finish(StatusFailed, PanicError{fmt.Errorf("%v: %w", recovered, ErrJobPanic)})
		}
	}()

	j.reportProgress(Progress{Elapsed: 0, Remaining: count})

	startedAt := time.Now()

	for currentCount := count - 1; currentCount >= 0; currentCount-- {
		// clip at the 99.99% percentile of exponential distribution, to prevent
		// a rare huge duration.
		clippedAt := 9.21034
		tickInterval := time.Duration(
			min(rand.ExpFloat64(), clippedAt) * float64(j.meanTickInterval),
		)

		select {
		case <-time.After(tickInterval):
			tick := Progress{
				Elapsed:   time.Since(startedAt),
				Remaining: currentCount,
			}
			if tick.IsTerminal() {
				j.finish(StatusCompleted, tick)

				return
			}

			j.reportProgress(tick)

		case <-ctx.Done():
			j.finish(StatusStopped, Stopped{Cause: ctx.Err()})

			return
		}
	}
}

func (j *Job) reportProgress(tick Progress) {
	j.mutex.Lock()
	defer j.mutex.Unlock()

	// Do not emit any tick after the job finishes.
	if j.status == StatusRunning {
		j.ticks = append(j.ticks, tick)
		close(j.changed)
		j.changed = make(chan struct{})
	}
}

// finish performs two actions under a single lock: the compare-and-set from
// RUNNING status, and the appending to the ticks.
func (j *Job) finish(terminalStatus Status, lastTick Tick) {
	j.mutex.Lock()
	defer j.mutex.Unlock()

	if j.status == StatusRunning {
		j.status = terminalStatus
		j.ticks = append(j.ticks, lastTick)
		close(j.changed)
		// Do not re-create j.changed channel, because no change is expected
		// after the job finishes.
	}
}
