package socks6

const (
	// TODO: IANA consideration
	SOCKS6CleartextPort = 1080
	SOCKS6TLSPort       = 8389
)

const (
	AuthenticationMethodNone             byte = 0
	AuthenticationMethodGSSAPI           byte = 1
	AuthenticationMethodUsernamePassword byte = 2
)

const (
	CommandNoop byte = iota
	CommandConnect
	CommandBind
	CommandUdpAssociate
)

const (
	AuthenticationReplySuccess = 0
	AuthenticationReplyFail    = 1
)

const (
	OperationReplySuccess byte = iota
	OperationReplyServerFailure
	OperationReplyNotAllowedByRule
	OperationReplyNetworkUnreachable
	OperationReplyHostUnreachable
	OperationReplyConnectionRefused
	OperationReplyTTLExpired
	OperationReplyAddressNotSupported
	OperationReplyTimeout
)

const (
	AddressTypeIPv4       byte = 1
	AddressTypeDomainName byte = 3
	AddressTypeIPv6       byte = 4
)

const (
	_ byte = iota
	UDPMessageAssociationInit
	UDPMessageAssociationAck
	UDPMessageDatagram
	UDPMessageError
)
