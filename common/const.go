package common

// ProtocolVersion is SOCKS 6 wireformat version
//
// TODO: set to const 6 and update comment when standardized
// 1xx: represent draft xx
// 2xx: based on draft xx
var ProtocolVersion byte = 111

const (
	CleartextPort = 1080
	// TODO: waiting for IANA consideration
	EncryptedPort = 8389
)
