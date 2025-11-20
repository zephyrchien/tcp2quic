## TCP2QUIC
TCP is so widely used, however QUIC may have a better performance. For softwares which use protocols built on TCP, this program helps them take FULL advantage of QUIC.

## Usage
```
#tcp->quic
tcp2quic -c <tcp_addr> <quic_addr> <sni=localhost>

#quic->tcp
tcp2quic -s <quic_addr> <tcp_addr> <common_name=localhost>
```

## Security
The server generates self-signed certificate automatically, with the common name(CN) "localhost" by default. While the client always SKIP verification during a TLS handshake. Also, 0-rtt is enabled, at the risk of suffering from replay attack or MITM attack.
<br>

In general, you should NEVER rely on this program for security, though the traffic is still encrypted.

