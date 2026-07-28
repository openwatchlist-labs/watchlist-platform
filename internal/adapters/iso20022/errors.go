package iso20022

import "errors"

var (
	ErrPayloadTooLarge              = errors.New("ISO 20022 payload exceeds configured limit")
	ErrUnsafeXML                    = errors.New("unsafe XML construct rejected")
	ErrInvalidEnvelope              = errors.New("invalid ISO 20022 envelope")
	ErrUnsupportedMessageDefinition = errors.New("unsupported ISO 20022 message definition")
	ErrPlanResolution               = errors.New("screening-plan resolution failed")
)
