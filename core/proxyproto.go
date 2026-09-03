/*

Self-contained HAProxy PROXY protocol (v1) support for the evilginx listener.

evilginx normally runs as the sole public host and reads the client's real IP
directly from the accepted TCP connection. Behind the agent's nginx TCP SNI
stream proxy, the connection to evilginx originates from 127.0.0.x, so the
victim's IP is otherwise lost (every capture reported "Local · 127.0.0.2").

The fix enables nginx's `proxy_protocol on;` for the stream server block, which
prepends a `PROXY TCP4 <client> <server> <sport> <dport>\r\n` header to each
accepted connection. This wrapper consumes that line on the first read (before
the TLS ClientHello) and reports the real client address via RemoteAddr(), so
session logging, blacklisting and geo all see the victim's actual IP.

It is deliberately backward-compatible: the header is only consumed when the
stream actually starts with `PROXY ` (a TLS ClientHello never does), so the
binary works whether or not nginx sends PROXY protocol — letting the two sides
be rolled out independently without an outage.

Vendored/offline build friendly: standard library only, no new dependency.

*/
package core

import (
	"bufio"
	"bytes"
	"net"
	"strconv"
	"strings"
)

type proxyProtoConn struct {
	net.Conn
	clientAddr net.Addr
	headerRead bool
	leftover   []byte
}

// wrapProxyProto wraps a connection and consumes a leading PROXY protocol v1
// header (when present) so downstream code sees the true client address.
func wrapProxyProto(c net.Conn) net.Conn {
	return &proxyProtoConn{Conn: c}
}

// Read consumes the PROXY header on the first call, then returns the real
// payload (e.g. the start of the TLS ClientHello) transparently.
func (p *proxyProtoConn) Read(b []byte) (int, error) {
	if !p.headerRead {
		if err := p.parseHeader(); err != nil {
			return 0, err
		}
	}
	if len(p.leftover) > 0 {
		n := copy(b, p.leftover)
		p.leftover = p.leftover[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// parseHeader peeks at the first bytes: if they are a PROXY header, consume it
// and record the client address; otherwise pass the stream through untouched.
// Any bytes buffered past the header (the TLS ClientHello) are preserved.
func (p *proxyProtoConn) parseHeader() error {
	br := bufio.NewReader(p.Conn)

	head, err := br.Peek(6)
	if err == nil && bytes.HasPrefix(head, []byte("PROXY ")) {
		if line, lerr := br.ReadBytes('\n'); lerr == nil {
			trimmed := strings.TrimRight(string(line), "\r\n")
			parts := strings.Split(trimmed, " ")
			// PROXY TCP4 <src_ip> <dst_ip> <src_port> <dst_port>
			if len(parts) >= 6 && parts[0] == "PROXY" && (parts[1] == "TCP4" || parts[1] == "TCP6") {
				if ip := net.ParseIP(parts[2]); ip != nil {
					if port, perr := strconv.Atoi(parts[4]); perr == nil {
						p.clientAddr = &net.TCPAddr{IP: ip, Port: port}
					}
				}
			}
		}
	}

	// Whatever bufio buffered (the rest of the ClientHello, or the first
	// segment of a non-PROXY connection) must be handed through, not dropped.
	p.headerRead = true
	if br.Buffered() > 0 {
		extra, _ := br.Peek(br.Buffered())
		p.leftover = append(p.leftover, extra...)
		_, _ = br.Discard(br.Buffered())
	}
	return nil
}

// RemoteAddr returns the real client address when a PROXY header was seen,
// falling back to the underlying connection address otherwise.
func (p *proxyProtoConn) RemoteAddr() net.Addr {
	if p.clientAddr != nil {
		return p.clientAddr
	}
	return p.Conn.RemoteAddr()
}
