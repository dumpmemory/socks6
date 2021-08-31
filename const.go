package socks6

const (
	SOCKS6CleartextPort = 1080
	// TODO: waiting for IANA consideration
	SOCKS6EncryptedPort = 8389
)

const (
	AuthenticationMethodNone             byte = 0
	AuthenticationMethodGSSAPI           byte = 1
	AuthenticationMethodUsernamePassword byte = 2
)
