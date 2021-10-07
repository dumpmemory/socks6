package main

import (
	"context"
	"crypto/tls"
	"log"
	"time"

	"github.com/studentmain/socks6"
	"github.com/studentmain/socks6/internal/lg"
)

const (
	debugKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAreOEK/j2T4xW1LLjtH9LCEw30kb6MYPdKwT9a0kYTeS1v3jz
aP9kmTaL+FOLfBd6xZ//4QIXONpomVvqWCZbs+XQYBKaYeL1jSxCuK5/K6ZNcUOD
PZdShacdS4O1XwLUQmW0PALf1Beb1Ma7wwFYan2qdWCOjKo3HvfbbUKTOHD5iWbs
SRqcD5ekAcs5t4eUuDmSJZc00RcV/rwRbXgyCwvU9xeBA3AhADdRdbU/KeUq1VA3
/UTeWIxCabvu7ebj+WuMqy6UrQtDJCNlezjJRh6UcpwKhTMhm7+zNCEd9oCAJKNt
nvVF2d+qVMlrMt/2sA0ecOlbHNndmMNqTYKoSwIDAQABAoIBAQCJp8fVK6SJurZu
cSNTm0WhzvyNyUR8+D+Ys72ONfI4j6rVZgGDiFJx+714m2KbnNbDJfNhg88wYa5W
YW411D/aPT7lHzT58rqixHwZSYJA4skBtglqM6XPSkklo6FsEohH+81fiIL6mqnx
GlY/fIwq2Uqc2xBeCM3UBTC+4Oo8zdwyT4srTlJWXGLkFBnGcka2QXAIyRyznkND
kzLNbKx/XuoHK0CYHW5ChIjmpmjvQZt6H8rAoCeUGKCiNN6SkMAWzg0nT1XtaYnj
+PT4zUHI/iAitoMHacsrgDuXVnA0IiRFWtegcb4ixlq8hFkxYhkNtxwfmhoOkpOW
nylSNtIZAoGBAN3yKNzzYcUdOaRbKLDmJfikfK2ZSveL/ha5S0oU4UiBsrlDpeCX
B7Y4gVl84nPlwpXDhPVvUyobS84X9/Q7iBAJJh4M5h34D3L1bi+JJH3/6GaNCeM5
d/MUcQocbKpziuuefq36rj9n3j+HfvzRckDgbylmb7jxiywoUc5/EueVAoGBAMiR
tle3xTyNSbodDguSL8MLzr5vEiE6rm4fZjKSXl1hZv8Z1yrSInxCBmRQo4tm+pr4
6yL48kfGkb6Xo39XH1qW/jRmnHDIM2Hw8fK51M44qEkzDVdfKyUHRzRIjNDRUf+4
gM8orLMuJAd+Uhh+iPNgx8lgy745AIgsEIUvddhfAoGBAK0a0Wo7XVcrCyk4fE00
xArg5+lSNVlL07qPfLxj+q3dkrLSo06/HSGvgpt0Pv8cBZ9fZpUy5c9iiMZOhXL0
95NiP1uSvexD7HDCIdVrho3LicxqVnrl+Lsbh2rWbp6nDYPmE3HIoh0L+xjbqlyv
Uwhsw+arYZoCsoSXUe7Xx7vdAoGAcNcBtlIOpmV68Dl+eGYTdvGCrEMC+Szxi8Ug
kx0j9/dfoe/gzReSDUR8Ih34FOqn3V5js7ZJYLZHsunPM0pJuoaul76PDyijN9v9
0yhXoHnhu+T8AYbqWBfDKJgUmTranjsoRORGXTx9SrX37A3scLinThWmKuwY74OS
+8taypMCgYA4Lqh4/GCISKBF+jvVpTO9hiwTFuuKM+yeDTfcypKCqNNJRoCv0r+T
mCe9sLh2AsQLwQvBvue07evyYrJaIc1s/toWqjqRhyHgboihPDgwswvDmjnG3RLZ
3zu/D3TJ+GsgJhAGPMylJgbJuUY7oOtUCHG/4RoUNQ31zRyj4Z56Hw==
-----END RSA PRIVATE KEY-----`

	debugPem = `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUTQsfaHflfPj5E48wWX10KirQm1gwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMTA3MjcxMzM5MTlaFw0zMTA3
MjUxMzM5MTlaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCt44Qr+PZPjFbUsuO0f0sITDfSRvoxg90rBP1rSRhN
5LW/ePNo/2SZNov4U4t8F3rFn//hAhc42miZW+pYJluz5dBgEpph4vWNLEK4rn8r
pk1xQ4M9l1KFpx1Lg7VfAtRCZbQ8At/UF5vUxrvDAVhqfap1YI6Mqjce99ttQpM4
cPmJZuxJGpwPl6QByzm3h5S4OZIllzTRFxX+vBFteDILC9T3F4EDcCEAN1F1tT8p
5SrVUDf9RN5YjEJpu+7t5uP5a4yrLpStC0MkI2V7OMlGHpRynAqFMyGbv7M0IR32
gIAko22e9UXZ36pUyWsy3/awDR5w6Vsc2d2Yw2pNgqhLAgMBAAGjUzBRMB0GA1Ud
DgQWBBRGe1mLiI1nILnyMHyS0+xXDMAwjDAfBgNVHSMEGDAWgBRGe1mLiI1nILny
MHyS0+xXDMAwjDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAK
79xS4dA/NhJ77/fF44GRH3anRTw38na8kEzhqjrMuHwWdtgObtP6gPSHJiSG268n
lKsQrdhzYfDcMFVxnjW4E3H9OVpvON2VxXU6m0lBNpOEnUGf92ZHlmCNzkTFsDVx
0WBmVLmfJZ3Ic7B2bRKLl1AKl1zXkhMpYO7xlnOzIdjCHgu68qfpikP/HkHeUlhw
w0d6vd+Vuhku06+R5Wf6IGuLFyAFMSqjzxsTrZJ5QfCpiT5N8Sp5xv7SfUWG+aCH
oGGJ+KZGw88sgiJhgZ7g7lfB1/AbjomhvUgqBzY74J0d+k1FUqJLNWZ+tF8U/4h2
fQIXRNDBdXLIdOAl2+PZ
-----END CERTIFICATE-----`
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)
	lg.MinimalLevel = lg.LvDebug
	kp, _ := tls.X509KeyPair([]byte(debugPem), []byte(debugKey))
	s := socks6.Server{
		CleartextPort: 10888,
		EncryptedPort: 10889,
		Address:       "0.0.0.0",
		Cert:          kp,
	}
	s.Start(context.Background(), nil)
	time.Sleep(8 * time.Hour)
}
