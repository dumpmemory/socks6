package common

// ProtocolVersion is SOCKS 6 wireformat version
//
// TODO: set to 6 when standardized
// 1xx: represent draft xx
// 2xx: based on draft xx
const ProtocolVersion byte = 111

const (
	CleartextPort = 1080
	// TODO: waiting for IANA consideration
	EncryptedPort = 8389
)
