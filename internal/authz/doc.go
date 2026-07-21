// Package authz decides whether an agent may perform an action, based on the
// role that the agent holds. An Authorizer holds the mapping from agent
// identifier to role, which is loaded once at start-up. A role that is not
// known is rejected as the mapping is loaded, and thereafter anything that a
// role does not grant is denied, as is every action by an agent without a role.
package authz
