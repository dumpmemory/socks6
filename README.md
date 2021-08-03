# SOCKS 6 Golang implementation

Not production ready.

## Progress

currently based on draft 11

### What works

? means not tested at all

- TCP relay
- Bind
- UDP
- Noop
- Session
- Happy Eyeball Option (RFC6555 only)
- IP DF, TTL, TOS Option ? (remote leg only)
- Bind with backlog ? (backlog is simulated) 
- TLS ?
- Client API ? (no bind)
- DTLS ?
- Token ?

### TODO list

- Other platform
- Port parity Option
- Authentication
- Test coverage
- Follow golang conventions
- ...

### Not TODO

If somebody implemented these feature, just send patch.

- TFO Option. 
    TFO is not supported in Go stdlib, need special OS API to establish TFO connection, need write a custom dialer to do that.
- MPTCP Option.
    Not supported in Go stdlib and some desktop OS (yet).
- UDP Error Option.
    Non privileged ICMP PacketConn in Go is not supported on some desktop OS (yet).


## Reference

- [SOCKS 6 draft GitHub repo](https://github.com/45G/socks6-draft)
- [SOCKS 6 draft IETF tracker](https://datatracker.ietf.org/doc/draft-olteanu-intarea-socks-6/)
- [go-shadowsocks2](https://github.com/shadowsocks/go-shadowsocks2)