// Package registry tracks running jobs and the agent that owns each one.
//
// A Registry owns its jobs' lifetimes: Create starts a job and registers it
// under a freshly minted ID, Find looks one up, and Shutdown stops every job
// and rejects further Creates. Lookups are owner-scoped, so an agent reaches
// only the jobs it started; a job owned by another agent is reported as not
// found, indistinguishably from one that does not exist.
//
// All Registry methods are safe for concurrent use by multiple goroutines.
package registry
