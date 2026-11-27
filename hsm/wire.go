package hsm

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Wire format: every message is a 2-byte big-endian length followed by that
// many bytes of ASCII.
//
//	request:  HHHH CC [;field]...
//	response: HHHH RR EE [;field]...
//
// HHHH is a four-character header the client chooses and the HSM echoes, CC
// the command, RR the response code, EE the error code. Fields are separated
// by ';' (no field in this command set can contain one).

// MaxMessage is the largest message accepted on the wire.
const MaxMessage = 32 * 1024

// ErrFrame reports a malformed message.
var ErrFrame = errors.New("hsm: malformed message")

// MarshalRequest encodes a request payload (without the length prefix).
func MarshalRequest(r Request) ([]byte, error) {
	if len(r.Header) != 4 || len(r.Command) != 2 {
		return nil, ErrFrame
	}
	return marshal(r.Header+r.Command, r.Fields)
}

// MarshalResponse encodes a response payload.
func MarshalResponse(r Response) ([]byte, error) {
	if len(r.Header) != 4 || len(r.Code) != 2 || len(r.Error) != 2 {
		return nil, ErrFrame
	}
	return marshal(r.Header+r.Code+r.Error, r.Fields)
}

func marshal(head string, fields []string) ([]byte, error) {
	var b strings.Builder
	b.WriteString(head)
	for _, f := range fields {
		if strings.ContainsAny(f, ";\x00") {
			return nil, ErrFrame
		}
		b.WriteByte(';')
		b.WriteString(f)
	}
	if b.Len() > MaxMessage {
		return nil, ErrFrame
	}
	return []byte(b.String()), nil
}

func splitFields(s string) []string {
	if s == "" {
		return []string{}
	}
	if s[0] != ';' {
		return nil
	}
	return strings.Split(s[1:], ";")
}

// UnmarshalRequest decodes a request payload.
func UnmarshalRequest(p []byte) (Request, error) {
	s := string(p)
	if len(s) < 6 {
		return Request{}, ErrFrame
	}
	f := splitFields(s[6:])
	if f == nil {
		return Request{}, ErrFrame
	}
	return Request{Header: s[:4], Command: s[4:6], Fields: f}, nil
}

// UnmarshalResponse decodes a response payload.
func UnmarshalResponse(p []byte) (Response, error) {
	s := string(p)
	if len(s) < 8 {
		return Response{}, ErrFrame
	}
	f := splitFields(s[8:])
	if f == nil {
		return Response{}, ErrFrame
	}
	return Response{Header: s[:4], Code: s[4:6], Error: s[6:8], Fields: f}, nil
}

// WriteFrame writes a length-prefixed message.
func WriteFrame(w io.Writer, p []byte) error {
	if len(p) > MaxMessage {
		return ErrFrame
	}
	buf := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(buf, uint16(len(p)))
	copy(buf[2:], p)
	_, err := w.Write(buf)
	return err
}

// ReadFrame reads a length-prefixed message.
func ReadFrame(r io.Reader) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n > MaxMessage {
		return nil, ErrFrame
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, err
	}
	return p, nil
}

// Server serves an HSM over TCP. Each connection is handled by its own
// goroutine and processes requests in order; clients that want parallelism
// open several connections, as with a real HSM.
type Server struct {
	HSM         *HSM
	Logger      *slog.Logger
	IdleTimeout time.Duration // 0 means 5 minutes

	mu    sync.Mutex
	ln    net.Listener
	conns map[net.Conn]struct{}
	wg    sync.WaitGroup
	done  atomic.Bool
}

// Serve accepts connections on ln until Close.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	s.ln = ln
	if s.conns == nil {
		s.conns = map[net.Conn]struct{}{}
	}
	s.mu.Unlock()
	for {
		c, err := ln.Accept()
		if err != nil {
			if s.done.Load() {
				return nil
			}
			return err
		}
		s.mu.Lock()
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go s.handle(c)
	}
}

func (s *Server) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func (s *Server) handle(c net.Conn) {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
		c.Close()
	}()
	idle := s.IdleTimeout
	if idle == 0 {
		idle = 5 * time.Minute
	}
	r := bufio.NewReader(c)
	for {
		_ = c.SetReadDeadline(time.Now().Add(idle))
		p, err := ReadFrame(r)
		if err != nil {
			return
		}
		req, err := UnmarshalRequest(p)
		var resp Response
		if err != nil {
			resp = Response{Header: "0000", Code: "ZZ", Error: InvalidInput, Fields: []string{}}
		} else {
			start := time.Now()
			resp = s.HSM.Execute(context.Background(), req)
			// Never log fields: they carry PIN blocks, PANs and keys.
			s.logger().Info("command", "cmd", req.Command, "err", resp.Error, "took", time.Since(start))
		}
		out, err := MarshalResponse(resp)
		if err != nil {
			return
		}
		if err := WriteFrame(c, out); err != nil {
			return
		}
	}
}

// Close stops accepting, closes open connections and waits for handlers.
func (s *Server) Close() error {
	s.done.Store(true)
	s.mu.Lock()
	var err error
	if s.ln != nil {
		err = s.ln.Close()
	}
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}

// Client is a connection to an HSM. It serializes requests on one
// connection; use one Client per goroutine or a pool for concurrency.
type Client struct {
	mu   sync.Mutex
	conn net.Conn
	r    *bufio.Reader
	seq  uint32
}

// Dial connects to an HSM server.
func Dial(ctx context.Context, addr string) (*Client, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Client{conn: c, r: bufio.NewReader(c)}, nil
}

// Do sends a command and waits for its response. The context deadline is
// applied to the connection; on timeout the connection is unusable and
// should be closed, since a late response would desynchronize it.
func (c *Client) Do(ctx context.Context, cmd string, fields ...string) (Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq = (c.seq + 1) % 10000
	hdr := fmt.Sprintf("%04d", c.seq)
	p, err := MarshalRequest(Request{Header: hdr, Command: cmd, Fields: fields})
	if err != nil {
		return Response{}, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.conn.SetDeadline(dl)
	} else {
		_ = c.conn.SetDeadline(time.Time{})
	}
	if err := WriteFrame(c.conn, p); err != nil {
		return Response{}, err
	}
	in, err := ReadFrame(c.r)
	if err != nil {
		return Response{}, err
	}
	resp, err := UnmarshalResponse(in)
	if err != nil {
		return Response{}, err
	}
	if resp.Header != hdr {
		return Response{}, fmt.Errorf("hsm: response header %s for request %s", resp.Header, hdr)
	}
	return resp, nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }
