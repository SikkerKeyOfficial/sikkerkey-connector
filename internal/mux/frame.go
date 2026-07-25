// Package mux implements the connector's half of the stream protocol.
//
// The wire format mirrors sikkerkey-tunnel's Frame.kt. A change to one is a
// change to both.
//
//	0        1                 9              N
//	+--------+-----------------+--------------+
//	| type:1 |  streamId:8 BE  |  payload...  |
//	+--------+-----------------+--------------+
//
// Stream ids are allocated by SikkerKey, monotonic per tunnel-service process
// rather than per connection, and never reused across a reconnect.
package mux

import (
	"encoding/binary"
	"errors"
)

const (
	TypeOpen    byte = 0x01
	TypeOpenOK  byte = 0x02
	TypeOpenErr byte = 0x03
	TypeData    byte = 0x04
	TypeClose   byte = 0x05

	headerLen = 9
)

var ErrShortFrame = errors.New("frame shorter than header")

// Open is the payload of a TypeOpen frame. It carries everything needed to
// verify the request against the public key pinned at enrollment.
type Open struct {
	Target string `json:"target"`
	// Address is host:port, inside the signed message, so this host dials what
	// SikkerKey signed.
	Address   string `json:"address"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

type Parsed struct {
	Type     byte
	StreamID uint64
	Payload  []byte
}

func Parse(b []byte) (*Parsed, error) {
	if len(b) < headerLen {
		return nil, ErrShortFrame
	}
	// The payload is copied rather than aliased: the caller's buffer belongs to
	// the WebSocket reader and is reused for the next frame.
	payload := make([]byte, len(b)-headerLen)
	copy(payload, b[headerLen:])
	return &Parsed{
		Type:     b[0],
		StreamID: binary.BigEndian.Uint64(b[1:9]),
		Payload:  payload,
	}, nil
}

func Encode(t byte, streamID uint64, payload []byte) []byte {
	out := make([]byte, headerLen+len(payload))
	out[0] = t
	binary.BigEndian.PutUint64(out[1:9], streamID)
	copy(out[headerLen:], payload)
	return out
}

func EncodeOpenOK(streamID uint64) []byte { return Encode(TypeOpenOK, streamID, nil) }

func EncodeOpenErr(streamID uint64, reason string) []byte {
	return Encode(TypeOpenErr, streamID, []byte(reason))
}

func EncodeData(streamID uint64, payload []byte) []byte {
	return Encode(TypeData, streamID, payload)
}

func EncodeClose(streamID uint64) []byte { return Encode(TypeClose, streamID, nil) }
