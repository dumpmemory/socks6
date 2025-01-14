# SOCKS 6 Golang implementation

Maybe production ready, if someone have a production, please let me know.

currently based on draft 12

## Usage

Use socks6.Server to create a SOCKS 6 over TCP/IP server.

If you need process SOCKS 6 connection in other protocol, named pipe, etc., use socks6.ServerWorker to process connection.

You can modify socks6.ServerWorker 's fields to customize it's behavior.

Use socks6.Client to create a SOCKS 6 over TCP/IP client.

Change socks6.Client.DialFunc to dial over other protocol.

SOCKS 6 wireformat parser and serializer is located in message package.

## Progress

Stand-alone server and SOCKS 5 to SOCKS 6 converter client is planned.

Many stack options require `setsockopt()`, which will (indirectly) cause the connetion can't closed by `net.Conn.Close()`.
Some even needs break TCP model.
A new network stack is needed in order to support them, likely coupled with OS TCP/IP stack.

## Reference

- [SOCKS 6 draft GitHub repo](https://github.com/45G/socks6-draft)
- [SOCKS 6 draft IETF tracker](https://datatracker.ietf.org/doc/draft-olteanu-intarea-socks-6/)
- [go-shadowsocks2](https://github.com/shadowsocks/go-shadowsocks2)
- [v2ray](https://github.com/v2fly/v2ray-core)
- [txthinking/socks5](https://github.com/txthinking/socks5)

--------

## Experimental/customized features

This implementation contains some experimental and customized features.

Experimental features are intended to integrate to RFC.
If they are not integrated eventually, it will either removed or become optional customized feature.

Customized features are designed to improve user experience, especially under eletronic warfare scenario,
which radar cross section (RCS) are important.
All of these features are optional.

(Radar: a device which determine some object's position and type,
by sending some carefully constructed data then read and analysis possible reflection data.)

### Consistent address format

See [https://github.com/45G/socks6-draft/issues/5](https://github.com/45G/socks6-draft/issues/5)

Use same address format in TCP and UDP message, to simplify address parsing. Not integrate to RFC yet, can't be disabled.

### Ignore fragmented request message

Optional. Used to mitigate large packet DDoS [1] attack and to help reduce server's RCS[2].

Implemented by only reading from buffer when parsing request message,
which is implemented by setting read timeout to 1us after accept connection and hope it works as intended/imagine.
It cause reflection only occured when incoming pulse is long enough and using special modulation,
effectively make reflection harder to occur, which in turn reduced RCS.

- [1] [https://datatracker.ietf.org/doc/html/draft-olteanu-intarea-socks-6-11#section-13.1](https://datatracker.ietf.org/doc/html/draft-olteanu-intarea-socks-6-11#section-13.1)
- [2] [https://censorbib.nymity.ch/#Alice2020a](https://censorbib.nymity.ch/#Alice2020a)

### Address dependent filtering NAT (Restricted cone)

Optional. In some sceneario, UDP Endpoint independent filtering (Full cone) NAT can reflect radar pulse, cause much higher RCS.
Switch to address dependent filtering can absorb incoming radar pulse, reduce RCS significantly without losing critical end-to-end property too much.

About UDP NAT behavior see [RFC4787](https://datatracker.ietf.org/doc/html/rfc4787)

### QUIC transport

Optional. Should belongs to another Internet Draft or a new Workgroup,<!--consider how we actually use SOCKS 5 and [what the most famous SOCKS 5 implementation has been done](https://www.eff.org/deeplinks/2015/08/speech-enables-speech-china-takes-aim-its-coders), I suggest call it Unauthenticated Firewall Traversal Workgroup.-->

[RFC9221](https://datatracker.ietf.org/doc/html/rfc9221) mentioned

> Unreliable QUIC datagrams can also be used to implement an IP packet tunnel over QUIC, such as for a Virtual Private Network (VPN).

And here comes <q>a Virtual Private Network (VPN)</q>.

Technically SOCKS works on Session Layer (L5), most VPN works on Network Layer (L3), but thanks for our great vendors and service providers, modern Internet even only need two transport layer protocols (By the way, that's why I choose shiny new QUIC transport instead of old school SCTP transport,<!--by the way, it's supposed to over IP instead of UDP, thanks Jon, at least UDP is just L4IP-->), unbreakable obstacle between the layers has been broken, we are going toward a layerless Internet which all nodes are equal, <!--but some nodes are more equal. The Internet revolution has been betrayed, my friend!-->

Not tested yet. Since there are no such Internet Draft not to mention Workgroup yet. Here's my simple draft.

#### Draft

[BCP14 boilerplate](https://datatracker.ietf.org/doc/html/rfc8174#section-2), you know what it is, omitted.

- All QUIC stream use same protocol with TCP, no "control stream"
- Client SHOULD try to authenticate over every stream until one stream finished authentication (either success or fail).
- Server SHOULD only authenticate first incoming stream, when fail, close entire conn.
- All stream in a connection are belongs to same session.

(stack option may wont works as expected?)

Per command requirement:
- CONNECT
    - (nothing)
- BIND
    - When backlog option enabled, server open a new stream to client, send remote's address via a operation reply (without client send anything). Only a backlog enabled stream per connection.
    - client can use streamid option to open multiple backlog bind
```
    c               s               r
    ---------------------------------
    ---#1 bind sa1-->
                    listen sa1
    <--#1 oprep sa1--
                    <---- sa1<ra1 ---

without streamid
    <--#2 oprep ra1--
    <--#2 relay -------------- ra1-->

with streamid
    <-#2 oprep ra1(#1)
    <--#2 relay -------------- ra1-->
``` 

- UDP
    - use assoc id to distinguish between streams
    - Client SHOULD send QUIC datagram
    - Client and server MAY use UDP over TCP on QUIC stream (to support QUIC impl without RFC9221 and muxconn with no dgram capability, i.e. SCTP)
    - Both side MUST NOT skip association check

New option:
    StreamID, contains a uint32, unique for each conn. Used by client to enable mux bind.
- non-mux conn MUST ignore it.
- In same conn, client MUST either always send it or not send it.
- When not send by client, client MUST NOT open more than 1 backlog bind per conn.
- Server MUST reply same stream id when ack mux bind

IANA consideration:
- socks6 over quic port
- streamid option

Normative ref:
- RFC9000 (quic)
- RFC9221 (quic dgram)
- BCP14 (keyword)
- I-D.socks6

Informative ref:
- RFC9260 (sctp)
- RFC6951 (sctp over udp)
