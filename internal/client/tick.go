package client

import (
	"bytes"
	"encoding/json"
	"fmt"

	fizzledv1 "github.com/tkngch/fizzled-go/internal/gen/fizzled/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// tickJSON is the canonical protobuf JSON of tick, on a single line.
func tickJSON(tick *fizzledv1.Tick) ([]byte, error) {
	var options protojson.MarshalOptions

	// Set EmitDefaultValues to true, to include `"remaining": 0` from the tick
	// that ends a job. Otherwise, proto3 would omit a zero-valued scalar.
	options.EmitDefaultValues = true

	encoded, err := options.Marshal(tick)
	if err != nil {
		return nil, fmt.Errorf("tick json: %w", err)
	}

	var compacted bytes.Buffer

	// Compact the JSON into a single line.
	err = json.Compact(&compacted, encoded)
	if err != nil {
		return nil, fmt.Errorf("tick json: %w", err)
	}

	return compacted.Bytes(), nil
}
