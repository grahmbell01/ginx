package core

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func newBytesReader(s string) io.Reader { return strings.NewReader(s) }

type pipeConn struct {
	reader io.Reader
	addr   net.Addr
	net.Conn
}

func (p *pipeConn) Read(b []byte) (int, error)      { return p.reader.Read(b) }
func (p *pipeConn) RemoteAddr() net.Addr            { return p.addr }
func (p *pipeConn) Close() error                    { return nil }
func (p *pipeConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *pipeConn) SetWriteDeadline(t time.Time) error { return nil }
func (p *pipeConn) SetDeadline(t time.Time) error      { return nil }

func newPipe(data string) *pipeConn {
	return &pipeConn{reader: newBytesReader(data), addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.9"), Port: 443}}
}

func TestProxyHeaderParsed(t *testing.T) {
	in := "PROXY TCP4 203.0.113.7 187.124.7.53 55555 443\r\n\x16\x03\x01\x02\x00\x00" // fake TLS first bytes
	w := wrapProxyProto(newPipe(in))
	b := make([]byte, 64)
	n, err := w.Read(b)
	if err != nil {
		t.Fatalf("read err: %v", err)
	}
	got := string(b[:n])
	want := "\x16\x03\x01\x02\x00\x00"
	if got != want {
		t.Fatalf("read-through mismatch: got %q want %q", got, want)
	}
	ra := w.RemoteAddr().String() // "203.0.113.7:55555"
	if ra != "203.0.113.7:55555" {
		t.Fatalf("RemoteAddr = %q, want 203.0.113.7:55555", ra)
	}
}

func TestNoHeaderPassthrough(t *testing.T) {
	in := "\x16\x03\x01\x02\x00\x00" // raw TLS, no PROXY header
	w := wrapProxyProto(newPipe(in))
	b := make([]byte, 64)
	n, err := w.Read(b)
	if err != nil {
		t.Fatalf("read err: %v", err)
	}
	if string(b[:n]) != in {
		t.Fatalf("passthrough mismatch: %q", string(b[:n]))
	}
	if w.RemoteAddr().String() != "127.0.0.9:443" {
		t.Fatalf("RemoteAddr should fall back to underlying, got %q", w.RemoteAddr().String())
	}
}

func TestSplitAcrossReads(t *testing.T) {
	in := "PROXY TCP4 203.0.113.7 187.124.7.53 55555 443\r\n\x16\x03"
	w := wrapProxyProto(newPipe(in))
	b := make([]byte, 1)
	total := []byte{}
	for {
		n, err := w.Read(b)
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("read err: %v", err)
		}
		total = append(total, b[:n]...)
		if n > 0 && b[0] == 0x03 {
			break
		}
	}
	if string(total) != "\x16\x03" {
		t.Fatalf("split read mismatch: %q", string(total))
	}
}
