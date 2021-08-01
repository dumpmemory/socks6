# SOCKS 6 Golang implementation

Not production ready.

## Progress

currently based on draft 11

### What works

- TCP relay
- Bind
- Some stack option (remote leg only)
- Noop ?
- Bind with backlog ? (backlog is simulated)
- Session ?
- TLS ?
- UDP ?
- Client API ? (no bind)
- DTLS ?

### TODO list

- Other platform
- Token
- Authentication
- Test coverage
- Follow golang conventions
- ...

### Not TODO

- TFO Option. 
    TFO is not supported in Go stdlib, need special OS API to establish TFO connection, need write a custom dialer to do that.
- MPTCP Option.
    Not supported in Go stdlib and some desktop OS (yet).

## Reference

- [SOCKS 6 draft GitHub repo](https://github.com/45G/socks6-draft)
- [SOCKS 6 draft IETF tracker](https://datatracker.ietf.org/doc/draft-olteanu-intarea-socks-6/)
- [go-shadowsocks2](https://github.com/shadowsocks/go-shadowsocks2)