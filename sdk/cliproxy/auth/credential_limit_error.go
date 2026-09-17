package auth

import (
	"net/http"
	"strings"
	"time"
)

// credentialLimitError reports that every candidate credential was refused by a
// local rpm/tpm/max_concurrent limit. It mirrors HomeConcurrencyBusyError so the
// HTTP layer emits 429 with Retry-After.
type credentialLimitError struct {
	cause      *Error
	retryAfter time.Duration
}

func newCredentialLimitError(message string, retryAfter time.Duration) *credentialLimitError {
	message = strings.TrimSpace(message)
	if message == "" {
		message = "credential limits exceeded"
	}
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	return &credentialLimitError{
		cause: &Error{
			Code:       "credential_limit_exceeded",
			Message:    message,
			Retryable:  true,
			HTTPStatus: http.StatusTooManyRequests,
		},
		retryAfter: retryAfter,
	}
}

func (e *credentialLimitError) Error() string {
	if e == nil || e.cause == nil {
		return ""
	}
	return e.cause.Error()
}

// Unwrap exposes the inner *Error for errors.As callers.
func (e *credentialLimitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (e *credentialLimitError) StatusCode() int {
	if e == nil || e.cause == nil {
		return 0
	}
	return e.cause.StatusCode()
}

func (e *credentialLimitError) RetryAfter() *time.Duration {
	if e == nil || e.retryAfter <= 0 {
		return nil
	}
	value := e.retryAfter
	return &value
}

func (e *credentialLimitError) SafeResponseHeaders() http.Header {
	if e == nil {
		return nil
	}
	return safeRetryAfterHeader(e.retryAfter)
}
