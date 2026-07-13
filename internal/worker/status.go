package worker

// Status reports job's status.
type Status string

const (
	// StatusRunning means the job is running.
	StatusRunning Status = "RUNNING"

	// StatusCompleted means the job finished without an error or an
	// interruption.
	StatusCompleted Status = "COMPLETED"

	// StatusStopped means the job was stopped or canceled.
	StatusStopped Status = "STOPPED"

	// StatusFailed means the job failed to complete.
	StatusFailed Status = "FAILED"
)
