package server

import (
	"context"

	"github.com/tkngch/fizzled-go/internal/authn"
)

// ContextWithAgentID is the context that mimics the one for an RPC with
// agentID. It lives in a test file rather than beside authorize, so that
// agentIDKey stays out of reach of a production build.
func ContextWithAgentID(ctx context.Context, agentID authn.AgentID) context.Context {
	return context.WithValue(ctx, agentIDKey{}, agentID)
}

// AgentIDFrom reads the agent id out of ctx, and returns false when no agent id
// is found in ctx.
func AgentIDFrom(ctx context.Context) (authn.AgentID, bool) {
	return agentIDFrom(ctx)
}
