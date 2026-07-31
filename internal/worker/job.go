package worker

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/tkngch/fizzled-go/internal/logging"
)

// Job is a stochastic countdown job.
type Job struct {
	id     JobID
	status Status

	ticks            []Tick
	meanTickInterval time.Duration

	cancel context.CancelFunc

	changed  chan struct{}
	finished chan struct{}

	logger *slog.Logger

	// mutex guards status and ticks together, so a terminal transition and
	// its sentinel append happen atomically as one unit.
	mutex sync.Mutex
}

// MaxCount is the largest count a job accepts.
const MaxCount = 100

// MeanTickInterval is the mean interval between a job's ticks. The countdown's
// stochasticity parameters are fixed policy, not a caller knob.
const MeanTickInterval = time.Second

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
//
// logger records the job's one terminal transition, with the underlying error
// when the job failed. A nil logger discards it.
func NewJob(
	ctx context.Context,
	jobID JobID,
	count int,
	meanTickInterval time.Duration,
	logger *slog.Logger,
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
		logger:           logging.OrDiscard(logger),
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
// returns the job's terminal status. It is StatusStopped when the cancellation
// drove the job from running to stopped, and the status the job had already
// reached otherwise, such as StatusCompleted when a natural completion won the
// race. It is never StatusRunning, because the job has finished by the time
// Stop returns. Concurrent calls all observe the same result, regardless of
// whether the call drives the cancellation.
func (j *Job) Stop() Status {
	j.cancel()
	<-j.finished

	return j.Status()
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
			j.finish(ctx, StatusFailed, PanicError{fmt.Errorf("%w: %w", recovered, ErrJobPanic)})
		default:
			j.finish(ctx, StatusFailed, PanicError{fmt.Errorf("%v: %w", recovered, ErrJobPanic)})
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
				j.finish(ctx, StatusCompleted, tick)

				return
			}

			j.reportProgress(tick)

		case <-ctx.Done():
			j.finish(ctx, StatusStopped, Stopped{Cause: ctx.Err()})

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

// finish moves the job to its terminal status and records the move. Only the
// call that wins the transition records it, so a job's end is logged exactly
// once however many triggers reach it.
func (j *Job) finish(ctx context.Context, terminalStatus Status, lastTick Tick) {
	if !j.setTerminal(terminalStatus, lastTick) {
		return
	}

	j.auditTransition(ctx, terminalStatus, lastTick)
}

// setTerminal performs two actions under a single lock: the compare-and-set
// from RUNNING status, and the appending to the ticks. It reports whether this
// call is the one that performed the transition.
func (j *Job) setTerminal(terminalStatus Status, lastTick Tick) bool {
	j.mutex.Lock()
	defer j.mutex.Unlock()

	if j.status != StatusRunning {
		return false
	}

	j.status = terminalStatus
	j.ticks = append(j.ticks, lastTick)
	close(j.changed)
	// Do not re-create j.changed channel, because no change is expected after
	// the job finishes.

	return true
}

// auditTransition records the job's one transition out of RUNNING.
//
// It is written here, where the transition happens, rather than where a tick is
// delivered: a job that no subscriber is streaming fails just the same, and one
// with two subscribers still fails only once. A failure's cause is withheld
// from the client, so this line is the only place it is recorded.
func (j *Job) auditTransition(ctx context.Context, terminalStatus Status, lastTick Tick) {
	attributes := []slog.Attr{
		slog.String("job_id", string(j.id)),
		slog.String("status", string(terminalStatus)),
	}

	level := slog.LevelInfo
	if terminalStatus == StatusFailed {
		level = slog.LevelError
	}

	// The cause, when the tick carries one. It is withheld from the client, so
	// this attribute is the only place it is recorded.
	failure, isFailure := lastTick.(PanicError)
	if isFailure {
		attributes = append(attributes, slog.String("error", failure.Error()))
	}

	// WithoutCancel, because a job stopped by cancellation would otherwise
	// record its own end through the context that ended it, and a handler is
	// free to drop a record whose context is already done.
	j.logger.LogAttrs(context.WithoutCancel(ctx), level, "job finished", attributes...)
}
