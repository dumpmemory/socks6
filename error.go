package socks6

import "errors"

var ErrTTLExpired = errors.New("ttl expired")
var ErrServerFailure = errors.New("socks 6 server failure")
var ErrUnexpectedMessage = errors.New("unexpected protocol message")
var ErrAssociationMismatch = errors.New("association mismatch")
