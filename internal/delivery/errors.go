package delivery

import "errors"

var (
	ErrInvalidRequest        = errors.New("invalid request")
	ErrUnauthorized          = errors.New("unauthorized")
	ErrForbidden             = errors.New("forbidden")
	ErrSecretUnavailable     = errors.New("secret unavailable")
	ErrLinkPasswordInvalid   = errors.New("link password invalid")
	ErrPayloadTooLarge       = errors.New("payload too large")
	ErrDependencyUnavailable = errors.New("dependency unavailable")
	ErrInternal              = errors.New("internal error")
)

type ErrorCode string

const (
	CodeInvalidRequest             ErrorCode = "INVALID_REQUEST"
	CodeUnauthorized               ErrorCode = "UNAUTHORIZED"
	CodeForbidden                  ErrorCode = "FORBIDDEN"
	CodeSecretUnavailable          ErrorCode = "SECRET_UNAVAILABLE"
	CodeLinkPasswordInvalid        ErrorCode = "LINK_PASSWORD_INVALID"
	CodeRateLimited                ErrorCode = "RATE_LIMITED"
	CodePayloadTooLarge            ErrorCode = "PAYLOAD_TOO_LARGE"
	CodeInternal                   ErrorCode = "INTERNAL_ERROR"
	CodeDependencyUnavailable      ErrorCode = "DEPENDENCY_UNAVAILABLE"
	CodeEmailDeliveryNotConfigured ErrorCode = "EMAIL_DELIVERY_NOT_CONFIGURED"
	CodeSMTPConfigurationError     ErrorCode = "SMTP_CONFIGURATION_ERROR"
)
