package server

import "errors"

var (
	// ErrEmptyAddress indicates that a Config names no address to listen on.
	ErrEmptyAddress = errors.New("empty address")

	// ErrShutdownGraceElapsed indicates that a shutdown ran out of grace with
	// streams still open, and cut them off.
	ErrShutdownGraceElapsed = errors.New("shutdown grace elapsed")
)

const (
	// internalErrorMessage is what an internal failure tells the caller. It
	// describes nothing on purpose: whatever went wrong is a server-side
	// detail.
	internalErrorMessage = "internal error"

	// unexpectedErrorMessage is the fixed description a failure tick carries,
	// withholding its cause for the same reason.
	unexpectedErrorMessage = "unexpected error"
)
