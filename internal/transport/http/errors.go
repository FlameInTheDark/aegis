// Package httpx implements the Fiber HTTP transport: routing, middleware,
// structured errors, pagination and request validation.
package httpx

import (
	"errors"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

// Error is the platform's structured error envelope.
type Error struct {
	Code      string        `json:"code"`
	Message   string        `json:"message"`
	Details   []ErrorDetail `json:"details,omitempty"`
	RequestID string        `json:"request_id,omitempty"`
	Warning   string        `json:"warning,omitempty"`
}

// ErrorDetail is a field-level validation detail.
type ErrorDetail struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Common error codes.
const (
	CodeBadRequest     = "bad_request"
	CodeUnauthorized   = "unauthorized"
	CodeForbidden      = "forbidden"
	CodeNotFound       = "not_found"
	CodeConflict       = "conflict"
	CodeValidation     = "validation_failed"
	CodeRateLimited    = "rate_limited"
	CodeScopeViolation = "scope_violation"
	CodeInternal       = "internal_error"
	CodeServiceUnavail = "service_unavailable"
)

// HTTPError is a functional error with status code.
type HTTPError struct {
	Status int
	Body   Error
}

func (h *HTTPError) Error() string { return h.Body.Error() }

// NewHTTPError builds an HTTPError.
func NewHTTPError(status int, code, msg string) *HTTPError {
	return &HTTPError{Status: status, Body: Error{Code: code, Message: msg}}
}

// Convenience constructors ---------------------------------------------------

func BadRequest(msg string) *HTTPError {
	return NewHTTPError(http.StatusBadRequest, CodeBadRequest, msg)
}
func Unauthorized(msg string) *HTTPError {
	return NewHTTPError(http.StatusUnauthorized, CodeUnauthorized, msg)
}
func Forbidden(msg string) *HTTPError { return NewHTTPError(http.StatusForbidden, CodeForbidden, msg) }
func NotFound(msg string) *HTTPError  { return NewHTTPError(http.StatusNotFound, CodeNotFound, msg) }
func Conflict(msg string) *HTTPError  { return NewHTTPError(http.StatusConflict, CodeConflict, msg) }
func RateLimited(msg string) *HTTPError {
	return NewHTTPError(http.StatusTooManyRequests, CodeRateLimited, msg)
}
func Internal(msg string) *HTTPError {
	return NewHTTPError(http.StatusInternalServerError, CodeInternal, msg)
}
func Unavailable(msg string) *HTTPError {
	return NewHTTPError(http.StatusServiceUnavailable, CodeServiceUnavail, msg)
}

// Validation builds a 422 validation error with field details.
func Validation(details []ErrorDetail) *HTTPError {
	return &HTTPError{Status: http.StatusUnprocessableEntity, Body: Error{
		Code: CodeValidation, Message: "request validation failed", Details: details,
	}}
}

// ScopeViolation is returned when a target is outside the authorized scope.
func ScopeViolation(msg string) *HTTPError {
	return &HTTPError{Status: http.StatusForbidden, Body: Error{
		Code: CodeScopeViolation, Message: msg,
		Warning: "The requested operation targets resources outside the authorized scope.",
	}}
}

// WriteError serializes any error into the structured envelope.
// Internal error details never reach clients (no stack traces).
func WriteError(c *fiber.Ctx, err error) {
	var he *HTTPError
	if !errors.As(err, &he) {
		he = Internal("an unexpected error occurred")
	}
	c.Status(he.Status)
	_ = c.JSON(he.Body)
}
