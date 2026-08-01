package client

import fizzledv1 "github.com/tkngch/fizzled-go/internal/gen/fizzled/v1"

// TickJSON encodes the ticks that StreamOutput yields.
func TickJSON(tick *fizzledv1.Tick) ([]byte, error) {
	return tickJSON(tick)
}

// ErrorFrom is the mapping from a gRPC status onto this package's sentinels.
func ErrorFrom(operation string, err error) error {
	return errorFrom(operation, err)
}
