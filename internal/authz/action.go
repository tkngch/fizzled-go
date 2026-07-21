package authz

// Action describes the action that a user/agent can take.
type Action string

const (
	// ActionStart is to create and start a job.
	ActionStart Action = "Start"

	// ActionStop is to stop an existing job.
	ActionStop Action = "Stop"

	// ActionGetStatus is to query the status of job.
	ActionGetStatus Action = "GetStatus"

	// ActionStreamOutput is to stream the output from a job.
	ActionStreamOutput Action = "StreamOutput"
)
