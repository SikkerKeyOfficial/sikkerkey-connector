package mux

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// maxSkew bounds how long a captured OPEN stays usable, matching the ±5 minutes
// machine auth allows.
const maxSkew = 5 * time.Minute

// Verifier checks that an OPEN came from SikkerKey, against the public key
// pinned at enrollment. Verification is offline.
type Verifier struct {
	pub ed25519.PublicKey

	// Seen nonces inside the skew window. In memory rather than on disk: a
	// restart drops the socket too, so no connection outlives the record.
	mu    sync.Mutex
	seen  map[string]time.Time
	swept time.Time
}

func NewVerifier(pinnedPublicKeyB64 string) (*Verifier, error) {
	raw, err := base64.StdEncoding.DecodeString(pinnedPublicKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode pinned key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pinned key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return &Verifier{pub: ed25519.PublicKey(raw), seen: make(map[string]time.Time)}, nil
}

// canonical must match TunnelSigner.canonicalOpen on the backend exactly.
func canonical(tunnelID string, streamID uint64, target, address string, timestamp int64, nonce string) string {
	return fmt.Sprintf("open:%s:%d:%s:%s:%d:%s", tunnelID, streamID, target, address, timestamp, nonce)
}

// Verify returns nil when the OPEN is authentic, unexpired, and unreplayed.
// The address and the stream id are both inside the signed message, so a
// signature cannot be moved to another endpoint or replayed on another stream.
func (v *Verifier) Verify(tunnelID string, streamID uint64, o Open) error {
	age := time.Since(time.Unix(o.Timestamp, 0))
	if age < -maxSkew || age > maxSkew {
		return fmt.Errorf("request expired")
	}

	sig, err := base64.StdEncoding.DecodeString(o.Signature)
	if err != nil {
		return fmt.Errorf("malformed signature")
	}

	msg := canonical(tunnelID, streamID, o.Target, o.Address, o.Timestamp, o.Nonce)
	if !ed25519.Verify(v.pub, []byte(msg), sig) {
		return fmt.Errorf("bad signature")
	}

	// Replay check AFTER the signature, so a forged request can't burn a
	// legitimate nonce.
	v.mu.Lock()
	defer v.mu.Unlock()
	v.sweepLocked()
	if _, dup := v.seen[o.Nonce]; dup {
		return fmt.Errorf("nonce reused")
	}
	v.seen[o.Nonce] = time.Now()
	return nil
}

// sweepLocked drops nonces older than the skew window, which are already
// rejected on their timestamp.
func (v *Verifier) sweepLocked() {
	now := time.Now()
	if now.Sub(v.swept) < time.Minute {
		return
	}
	v.swept = now
	for nonce, at := range v.seen {
		if now.Sub(at) > maxSkew {
			delete(v.seen, nonce)
		}
	}
}
