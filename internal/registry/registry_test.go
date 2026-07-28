package registry_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/tkngch/fizzled-go/internal/authn"
	"github.com/tkngch/fizzled-go/internal/registry"
	"github.com/tkngch/fizzled-go/internal/worker"
)

const (
	agentSmith authn.AgentID = "smith"
	agentJones authn.AgentID = "jones"
)

func TestRegistry(t *testing.T) {
	t.Parallel()

	reg := registry.New()
	t.Cleanup(reg.Shutdown)

	jobID, err := reg.Create(t.Context(), agentSmith, 10)
	if err != nil {
		t.Fatalf("failed to create a job in the registry: %s", err)
	}

	job := mustFindJob(t, reg, agentSmith, jobID)

	if job.ID() != jobID {
		t.Errorf("expected [%s] jobID, got [%s]", jobID, job.ID())
	}

	if job.Status() != worker.StatusRunning {
		t.Errorf("expected running job, got %s", job.Status())
	}
}

func TestRegistryContextCancel(t *testing.T) {
	t.Parallel()

	reg := registry.New()
	t.Cleanup(reg.Shutdown)

	ctx, cancel := context.WithCancel(t.Context())

	jobID, err := reg.Create(ctx, agentSmith, 10)
	if err != nil {
		t.Fatalf("failed to create a job in the registry: %s", err)
	}

	job, isFound := reg.Find(agentSmith, jobID)
	if !isFound {
		t.Fatalf("created job not found")
	}

	cancel()

	if job.Status() != worker.StatusRunning {
		t.Errorf(
			"expected the job to be running after canceling the context, got %s",
			job.Status(),
		)
	}
}

func TestRegistryCreate(t *testing.T) {
	t.Parallel()

	reg := registry.New()
	t.Cleanup(reg.Shutdown)

	type created struct {
		jobID worker.JobID
		err   error
	}

	concurrency := 10

	results := make(chan created, concurrency)
	for range concurrency {
		go func() {
			jobID, err := reg.Create(t.Context(), agentSmith, 10)
			results <- created{jobID, err}
		}()
	}

	jobIDs := make(map[worker.JobID]bool)

	for range concurrency {
		result := <-results
		if result.err != nil {
			t.Fatalf("unexpected error: %s", result.err)
		}

		_, isFound := jobIDs[result.jobID]
		if isFound {
			t.Errorf("job-id duplicated: %s", result.jobID)
		}

		jobIDs[result.jobID] = true
	}

	for jobID := range jobIDs {
		job, isFound := reg.Find(agentSmith, jobID)
		if job == nil || !isFound {
			t.Errorf("created job not found: %s", jobID)
		}
	}
}

// TestRegistryCreateInvalidCount asserts that the job's own validation error
// survives the registry's wrapping, so a caller can map it onto its own
// invalid-argument response.
func TestRegistryCreateInvalidCount(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		count int
	}{
		{"zero count", 0},
		{"negative count", -10},
		{"too large count", worker.MaxCount + 1},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				reg := registry.New()
				t.Cleanup(reg.Shutdown)

				jobID, err := reg.Create(t.Context(), agentSmith, testCase.count)
				if !errors.Is(err, worker.ErrInvalidCount) {
					t.Errorf("expected invalid-count error, got [%s]", err)
				}

				if jobID != "" {
					t.Errorf("expected empty job-id, got [%s]", jobID)
				}
			},
		)
	}
}

func TestRegistryFind(t *testing.T) {
	t.Parallel()

	reg := registry.New()
	t.Cleanup(reg.Shutdown)

	jobIDs := make(map[authn.AgentID]worker.JobID)

	jobIDs[agentSmith] = mustCreateJob(t, reg, agentSmith)
	jobIDs[agentJones] = mustCreateJob(t, reg, agentJones)

	for _, agent := range []authn.AgentID{agentSmith, agentJones, "ghost"} {
		for owner, jobID := range jobIDs {
			job, isFound := reg.Find(agent, jobID)
			if agent == owner {
				// agent is the owner
				if job == nil || !isFound {
					t.Errorf("job is not found by owner")
				}
			} else {
				// agent is not the owner
				if job != nil || isFound {
					t.Errorf("job is found by non-owner")
				}
			}
		}
	}

	job, isFound := reg.Find(agentSmith, "invalid")
	if job != nil || isFound {
		t.Fatalf("a job is unexpectedly found: %v %v", job, isFound)
	}
}

// TestRegistryShutdown races concurrent Create calls against Shutdown and
// asserts that once Shutdown returns, every job in the registry has stopped.
func TestRegistryShutdown(t *testing.T) {
	t.Parallel()

	reg := registry.New()
	t.Cleanup(reg.Shutdown)

	type created struct {
		jobID worker.JobID
		err   error
	}

	concurrency := 32
	results := make(chan created, concurrency)
	ready := make(chan bool, concurrency)

	var creators sync.WaitGroup
	for range concurrency {
		creators.Go(func() {
			ready <- true

			jobID, err := reg.Create(t.Context(), agentSmith, 10)
			results <- created{jobID, err}
		})
	}

	// Wait for every creator to start, to give them a head start on the
	// registry's mutex. This makes an interleaving likely but not certain: an
	// creator can send on ready and still not reach Create before Shutdown
	// takes the mutex, so which side wins is unspecified.
	for range concurrency {
		<-ready
	}

	reg.Shutdown()
	creators.Wait()
	close(results)

	for result := range results {
		if result.err != nil && !errors.Is(result.err, registry.ErrNotAcceptingJobs) {
			t.Errorf("expected not-accepting-jobs error, got %s", result.err)
		}

		if result.err != nil {
			continue
		}

		job := mustFindJob(t, reg, agentSmith, result.jobID)

		if job.Status() != worker.StatusStopped {
			t.Errorf("expected stopped status, got %s [%s]", job.Status(), result.jobID)
		}
	}
}

// TestRegistryShutdownStopsJobs pins Shutdown's contract deterministically.
func TestRegistryShutdownStopsJobs(t *testing.T) {
	t.Parallel()

	reg := registry.New()
	t.Cleanup(reg.Shutdown)

	jobID := mustCreateJob(t, reg, agentSmith)
	job := mustFindJob(t, reg, agentSmith, jobID)

	reg.Shutdown()

	if job.Status() != worker.StatusStopped {
		t.Errorf("expected stopped status after shutdown, got %s", job.Status())
	}
}

// TestRegistryCreateAfterShutdown pins the post-shutdown rejection.
func TestRegistryCreateAfterShutdown(t *testing.T) {
	t.Parallel()

	reg := registry.New()
	reg.Shutdown()

	jobID, err := reg.Create(t.Context(), agentSmith, 10)
	if !errors.Is(err, registry.ErrNotAcceptingJobs) {
		t.Errorf("expected not-accepting-jobs error, got [%s]", err)
	}

	if jobID != "" {
		t.Errorf("expected empty job-id, got [%s]", jobID)
	}
}

func mustCreateJob(t *testing.T, reg *registry.Registry, agentID authn.AgentID) worker.JobID {
	t.Helper()

	jobID, err := reg.Create(t.Context(), agentID, 10)
	if err != nil {
		t.Fatalf("unexpected error in creating a job: %s", err)
	}

	return jobID
}

func mustFindJob(
	t *testing.T,
	reg *registry.Registry,
	agent authn.AgentID,
	jobID worker.JobID,
) *worker.Job {
	t.Helper()

	job, isFound := reg.Find(agent, jobID)
	if job == nil || !isFound {
		t.Fatalf("job is not found for agent %s: %s", agent, jobID)
	}

	return job
}
