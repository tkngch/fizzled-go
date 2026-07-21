package registry

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/tkngch/fizzled-go/internal/authz"
	"github.com/tkngch/fizzled-go/internal/worker"
)

// Registry keeps records of all jobs.
type Registry struct {
	records map[authz.AgentID]*record

	// mutex guards records and isAcceptingJobs together, so Create's flag check
	// and its job registration happen as one unit, and Shutdown can never
	// snapshot a registry that an in-flight Create is about to append.
	mutex sync.Mutex

	isAcceptingJobs bool
}

// ErrNotAcceptingJobs indicates that Registry.Shutdown was called and no job
// can be created and added to the registry.
var ErrNotAcceptingJobs = errors.New("not accepting jobs")

// New creates a fresh Registry with no record.
func New() *Registry {
	return &Registry{
		records:         make(map[authz.AgentID]*record),
		mutex:           sync.Mutex{},
		isAcceptingJobs: true,
	}
}

// Create starts a job that counts down from count for the agent, and registers
// it under a freshly minted JobID. The job is queryable and stoppable the
// instant Create returns.
//
// ctx carries request-scoped values only. Create detaches it, so cancelling ctx
// does not stop the job; only Job.Stop or Registry.Shutdown does.
//
// Create returns ErrNotAcceptingJobs once Shutdown has been called. It wraps
// the job's validation errors, such that errors.Is reports
// worker.ErrInvalidCount when count is out of range.
func (r *Registry) Create(
	ctx context.Context,
	agentID authz.AgentID,
	count int,
) (worker.JobID, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Read the flag and mint the job under one lock acquisition. That stops
	// this body from racing with Shutdown's snapshot: a job can never be
	// created after Shutdown has snapshotted.
	if !r.isAcceptingJobs {
		return "", fmt.Errorf("registry-create: %w", ErrNotAcceptingJobs)
	}

	// The Registry owns the job's lifetime, not ctx: cancelling ctx does not
	// stop the job; only Job.Stop or Registry.Shutdown does.
	jobCtx := context.WithoutCancel(ctx)

	rec, isFound := r.records[agentID]
	if !isFound {
		rec = newRecord(agentID)
	}

	jobID, err := rec.create(jobCtx, count)
	if err != nil {
		return "", fmt.Errorf("registry-create: %w", err)
	}

	if !isFound {
		// Store the record only after a job is created, so the map is free from
		// empty records that would waste the memory.
		r.records[agentID] = rec
	}

	return jobID, nil
}

// Find looks for a job that is owned by the agent. It returns nil with false if
// no job is found. Otherwise it returns a pointer to Job along with true bool.
//
// A job owned by another agent is reported as not found, indistinguishably from
// one that does not exist. Keep the two conflated: telling them apart would let
// an agent probe for the existence of other agents' jobs.
func (r *Registry) Find(agentID authz.AgentID, jobID worker.JobID) (*worker.Job, bool) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	rec, isFound := r.records[agentID]
	if !isFound {
		return nil, false
	}

	return rec.find(jobID)
}

// Shutdown stops every job and blocks until they have all finished. Once it is
// called, Create returns ErrNotAcceptingJobs.
//
// Shutdown is idempotent and safe to call concurrently: each call stops the
// same jobs, and stopping an already-stopped job is a no-op.
func (r *Registry) Shutdown() {
	r.mutex.Lock()
	r.isAcceptingJobs = false

	jobs := make([]*worker.Job, 0)
	for _, rec := range r.records {
		jobs = slices.AppendSeq(jobs, rec.allJobs())
	}

	r.mutex.Unlock()

	var waitGroup sync.WaitGroup

	for _, job := range jobs {
		waitGroup.Go(func() { job.Stop() })
	}

	waitGroup.Wait()
}
