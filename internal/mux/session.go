package mux

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// dialTimeout bounds how long a target gets to accept before the open is
// refused.
const dialTimeout = 10 * time.Second

// readBuf is the chunk size for target-to-SikkerKey traffic. One frame per read.
const readBuf = 32 * 1024

// Send is how a session writes a frame back to SikkerKey. Implementations must
// be safe for concurrent use, since every open stream writes through it.
type Send func(frame []byte) error

// Session owns the streams on one connector connection.
type Session struct {
	tunnelID string
	verifier *Verifier
	send     Send

	mu      sync.Mutex
	streams map[uint64]net.Conn
}

func NewSession(tunnelID string, verifier *Verifier, send Send) *Session {
	return &Session{
		tunnelID: tunnelID,
		verifier: verifier,
		send:     send,
		streams:  make(map[uint64]net.Conn),
	}
}

// Handle dispatches one frame from SikkerKey.
func (s *Session) Handle(f *Parsed) {
	switch f.Type {
	case TypeOpen:
		go s.open(f)
	case TypeData:
		s.write(f.StreamID, f.Payload)
	case TypeClose:
		s.closeStream(f.StreamID)
	default:
		log.Printf("mux: unknown frame type %d on stream %d", f.Type, f.StreamID)
	}
}

// CloseAll drops every stream, for when the connection to SikkerKey ends.
func (s *Session) CloseAll() {
	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.streams))
	for id, c := range s.streams {
		conns = append(conns, c)
		delete(s.streams, id)
	}
	s.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

func (s *Session) open(f *Parsed) {
	var o Open
	if err := json.Unmarshal(f.Payload, &o); err != nil {
		s.refuse(f.StreamID, "malformed open")
		return
	}

	// Verified before anything in the request is acted on, including resolving
	// the target name.
	if err := s.verifier.Verify(s.tunnelID, f.StreamID, o); err != nil {
		log.Printf("mux: refused open of stream %d: %v", f.StreamID, err)
		s.refuse(f.StreamID, "unauthorized")
		return
	}

	conn, err := net.DialTimeout("tcp", o.Address, dialTimeout)
	if err != nil {
		log.Printf("mux: stream %d could not reach target %q: %v", f.StreamID, o.Target, err)
		s.refuse(f.StreamID, "target unreachable")
		return
	}

	s.mu.Lock()
	// Stream ids are never reused, so a duplicate means the two sides have
	// diverged. The live stream is kept.
	if _, exists := s.streams[f.StreamID]; exists {
		s.mu.Unlock()
		conn.Close()
		s.refuse(f.StreamID, "duplicate stream")
		return
	}
	s.streams[f.StreamID] = conn
	s.mu.Unlock()

	if err := s.send(EncodeOpenOK(f.StreamID)); err != nil {
		s.closeStream(f.StreamID)
		return
	}
	log.Printf("mux: stream %d open to %q", f.StreamID, o.Target)

	go s.pump(f.StreamID, conn)
}

// pump carries target-to-SikkerKey bytes until either end goes away.
func (s *Session) pump(streamID uint64, conn net.Conn) {
	buf := make([]byte, readBuf)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if sendErr := s.send(EncodeData(streamID, buf[:n])); sendErr != nil {
				break
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("mux: stream %d read ended: %v", streamID, err)
			}
			break
		}
	}
	// Report the target's close to SikkerKey.
	s.mu.Lock()
	_, stillOpen := s.streams[streamID]
	delete(s.streams, streamID)
	s.mu.Unlock()
	conn.Close()
	if stillOpen {
		_ = s.send(EncodeClose(streamID))
	}
}

func (s *Session) write(streamID uint64, payload []byte) {
	s.mu.Lock()
	conn := s.streams[streamID]
	s.mu.Unlock()
	if conn == nil {
		// Data for a stream that has already gone. Normal during teardown.
		return
	}
	if _, err := conn.Write(payload); err != nil {
		log.Printf("mux: stream %d write failed: %v", streamID, err)
		s.closeStream(streamID)
	}
}

func (s *Session) closeStream(streamID uint64) {
	s.mu.Lock()
	conn := s.streams[streamID]
	delete(s.streams, streamID)
	s.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

func (s *Session) refuse(streamID uint64, reason string) {
	if err := s.send(EncodeOpenErr(streamID, reason)); err != nil {
		log.Printf("mux: could not report refusal of stream %d: %v", streamID, err)
	}
}
