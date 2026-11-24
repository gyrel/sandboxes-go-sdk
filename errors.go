package sandboxes

import (
	"context"
	"errors"
	"io"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const errorCodeInvalidArgument = "invalid_argument"
const errorCodeUnsupported = "unsupported"
const errorCodeInternal = "internal"
const errorCodeApprovalProviderUnavailable = "approval_provider_unavailable"

// ErrApprovalProviderUnavailable reports that the daemon has no trusted host
// approval provider, so it refused an APPROVE decision, an EXACT persist scope
// or a reference/command custom secret. The SDK never downgrades these
// requests. Match it with errors.Is.
var ErrApprovalProviderUnavailable error = &Error{
	Code:    errorCodeApprovalProviderUnavailable,
	Message: "trusted approval provider is unavailable",
}

// Is reports whether target is a typed error with the same code, so the
// sentinel values above match the errors returned by the client.
func (e *Error) Is(target error) bool {
	var typed *Error
	return e.Code != "" && errors.As(target, &typed) && typed.Code == e.Code
}

// mapApprovalUnavailable maps FAILED_PRECONDITION from approval-gated calls to
// ErrApprovalProviderUnavailable and every other status through mapError.
func mapApprovalUnavailable(err error) error {
	if err == nil {
		return nil
	}
	if status.Code(err) == codes.FailedPrecondition {
		return &Error{Code: errorCodeApprovalProviderUnavailable, Message: status.Convert(err).Message()}
	}
	return mapError(err)
}

func mapError(err error) error {
	if err == nil {
		return nil
	}
	var typed *Error
	if errors.As(err, &typed) {
		return typed
	}
	if errors.Is(err, io.EOF) {
		return io.EOF
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}

	code := errorCodeInternal
	retryable := false
	switch status.Code(err) {
	case codes.NotFound:
		code = "not_found"
	case codes.AlreadyExists:
		code = "already_exists"
	case codes.Aborted, codes.FailedPrecondition:
		code = "conflict"
	case codes.InvalidArgument:
		code = errorCodeInvalidArgument
	case codes.PermissionDenied, codes.Unauthenticated:
		code = "permission_denied"
	case codes.Unavailable:
		code, retryable = "unavailable", true
	case codes.DeadlineExceeded:
		code, retryable = "deadline_exceeded", true
	case codes.ResourceExhausted:
		code, retryable = "resource_exhausted", true
	}
	return &Error{Code: code, Message: status.Convert(err).Message(), Retryable: retryable}
}
