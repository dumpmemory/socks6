package main

type Config struct {
	CleartextPort uint16
	EncryptedPort uint16

	Address  string
	LogLevel int

	CertFile string
	KeyFile  string
}
