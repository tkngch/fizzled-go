package registry

import (
	"context"
	"fmt"
	"iter"
	"maps"

	"github.com/tkngch/fizzled-go/internal/authn"
	"github.com/tkngch/fizzled-go/internal/worker"
)

// record holds one agent's jobs and the counter to mint their JobIDs. record is
// not guarded by Mutex and is not concurrency-safe. A caller, Registry, has to
// guard its access.
type record struct {
	agentID authn.AgentID
	counter int
	jobs    map[worker.JobID]*worker.Job
}

func newRecord(agentID authn.AgentID) *record {
	return &record{
		agentID: agentID,
		counter: 0,
		jobs:    make(map[worker.JobID]*worker.Job),
	}
}

// create starts a job, registers it under a freshly minted ID, and advances the
// counter.
func (r *record) create(ctx context.Context, count int) (worker.JobID, error) {
	jobID := worker.JobID(fmt.Sprintf("%s/%d", r.agentID, r.counter))

	job, err := worker.NewJob(ctx, jobID, count, worker.MeanTickInterval)
	if err != nil {
		return "", fmt.Errorf("record-create [agent %s]: %w", r.agentID, err)
	}

	r.counter++
	r.jobs[jobID] = job

	return jobID, nil
}

func (r *record) find(jobID worker.JobID) (*worker.Job, bool) {
	job, isFound := r.jobs[jobID]

	return job, isFound
}

func (r *record) allJobs() iter.Seq[*worker.Job] {
	return maps.Values(r.jobs)
}
