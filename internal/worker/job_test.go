package worker_test

import (
	"context"
	"errors"
	"iter"
	"math"
	"slices"
	"testing"
	"time"

	"github.com/tkngch/fizzled-go/internal/worker"
)

func TestNewJob(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		count        int
		meanInterval time.Duration
		expectedErr  error
	}{
		{"positive count", 10, time.Second, nil},
		{"large count", worker.MaxCount, time.Second, nil},
		{"zero count", 0, time.Second, worker.ErrInvalidCount},
		{"negative count", -10, time.Second, worker.ErrInvalidCount},
		{"too large count", worker.MaxCount + 1, time.Second, worker.ErrInvalidCount},
		{"very large count", math.MaxInt, time.Second, worker.ErrInvalidCount},
		{"zero interval", 10, 0, worker.ErrInvalidMeanInterval},
		{"negative interval", 10, -time.Second, worker.ErrInvalidMeanInterval},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				jobID := worker.JobID(testCase.name)

				job, err := worker.NewJob(
					t.Context(),
					jobID,
					testCase.count,
					testCase.meanInterval,
				)
				if testCase.expectedErr != nil {
					if !errors.Is(err, testCase.expectedErr) {
						t.Errorf("expected error [%s], got [%s]", testCase.expectedErr, err)
					}

					if job != nil {
						t.Fatalf("expected nil job from NewJob(), got non-nil")
					}

					return
				}

				if err != nil {
					t.Fatalf("unexpected error from NewJob(): %s", err)
				}

				if job.ID() != jobID {
					t.Errorf("expected [%s] as a job id, got [%s]", jobID, job.ID())
				}

				assertJobStatus(t, worker.StatusRunning, job.Status())
			},
		)
	}
}

func TestJobStop(t *testing.T) {
	t.Parallel()

	job, err := worker.NewJob(t.Context(), worker.JobID("test job stop"), 10, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error from NewJob(): %s", err)
	}

	isStopped := job.Stop()
	if !isStopped {
		t.Errorf("expected true from job.Stop()")
	}

	assertJobStatus(t, worker.StatusStopped, job.Status())

	isStopped = job.Stop()
	if !isStopped {
		t.Errorf("expected true from job.Stop()")
	}

	assertJobStatus(t, worker.StatusStopped, job.Status())

	ticks := slices.Collect(job.Ticks(t.Context()))

	if len(ticks) < 2 {
		t.Fatalf("expected the initial tick and the terminal tick at least")
	}

	stopped, isStopped := ticks[len(ticks)-1].(worker.Stopped)
	if !isStopped {
		t.Fatalf("expected a stopped as the terminal tick, got %v instead", ticks[len(ticks)-1])
	}

	if !stopped.IsTerminal() {
		t.Errorf("expected a terminal stop")
	}

	if !errors.Is(stopped.Cause, context.Canceled) {
		t.Errorf("expected %s, got %s instead", context.Canceled, stopped.Cause)
	}

	stopped, isStopped = ticks[len(ticks)-2].(worker.Stopped)
	if isStopped {
		t.Errorf("expected one failure, got two: %v", stopped)
	}
}

func TestJobTicks(t *testing.T) {
	t.Parallel()

	count := 2
	job := mustNewJob(t, "test job ticks", count)

	results := make(chan []worker.Tick)

	consumerCount := 10
	for range consumerCount {
		go func() {
			ticks := slices.Collect(job.Ticks(t.Context()))
			results <- ticks
		}()
	}

	for range consumerCount {
		ticks := <-results

		if len(ticks) != count+1 {
			t.Fatalf("expected length %d, got %d", count+1, len(ticks))
		}

		assertProgressTicks(t, ticks, count)
	}

	assertJobStatus(t, worker.StatusCompleted, job.Status())
}

func TestJobTicksInterrupted(t *testing.T) {
	t.Parallel()

	count := 10

	job, err := worker.NewJob(
		t.Context(),
		worker.JobID("test job ticks interrupted"),
		count,
		time.Minute,
	)
	if err != nil {
		t.Fatalf("unexpected error from NewJob(): %s", err)
	}

	t.Run(
		"canceled",
		func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())

			collected := make(chan []worker.Tick)
			go func() {
				collected <- slices.Collect(job.Ticks(ctx))
			}()

			cancel()

			ticks := <-collected
			if len(ticks) >= count {
				t.Fatalf("expected partial ticks, got %d ticks", len(ticks))
			}

			assertProgressTicks(t, ticks, count)

			// Canceling the iterator should not cancel the job itself.
			assertJobStatus(t, worker.StatusRunning, job.Status())
		},
	)
	t.Run(
		"stop early",
		func(t *testing.T) {
			t.Parallel()

			next, stop := iter.Pull(job.Ticks(t.Context()))
			defer stop()

			tick, ok := next()
			if !ok {
				t.Fatalf("expected at least one tick")
			}

			switch tck := tick.(type) {
			case worker.PanicError:
				t.Fatalf("unexpected panic: %v", tck)
			default:
			}

			stop()

			// An early-stop in consuming ticks should not kill the job itself.
			assertJobStatus(t, worker.StatusRunning, job.Status())
		},
	)
}

func assertJobStatus(t *testing.T, expected, actual worker.Status) {
	t.Helper()

	if expected != actual {
		t.Errorf("expected %s status, got %s instead", expected, actual)
	}
}

func assertProgressTicks(t *testing.T, ticks []worker.Tick, count int) {
	t.Helper()

	progresses := make([]worker.Progress, 0, len(ticks))
	for idx, tick := range ticks {
		switch tck := tick.(type) {
		case worker.Progress:
			progresses = append(progresses, tck)
			if idx > 0 && tck.Elapsed < progresses[idx-1].Elapsed {
				t.Errorf(
					"expected monotonically increasing tick.Elapsed, got ticks[%d].Elapsed < ticks[%d].Elapsed",
					idx,
					idx-1,
				)
			}

			if tck.Remaining != count-idx {
				t.Fatalf(
					"expected %d for ticks[%d].Remaining, got %d",
					count-idx,
					idx,
					tck.Remaining,
				)
			}

		default:
			t.Fatalf("unexpected non-progress tick: %v", tck)
		}
	}
}

func mustNewJob(t *testing.T, jobID string, count int) *worker.Job {
	t.Helper()

	job, err := worker.NewJob(t.Context(), worker.JobID(jobID), count, time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error from NewJob(): %s", err)
	}

	status := job.Status()
	if status != worker.StatusRunning {
		t.Fatalf("expected RUNNING status for a new job, got %s", status)
	}

	return job
}
