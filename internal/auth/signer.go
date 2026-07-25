// Package auth handles Ed25519 request signing for connector authentication.
//
// Every request is signed with a private key that never leaves this host, and
// SikkerKey holds only the public half. The signed payload is byte-identical to
// the CLI's (see sikkerkey-cli/internal/auth), because the same verifier runs on
// the other end. The id header carries the tunnel id.
//
// The opposite direction, where SikkerKey proves itself to this connector before
// a stream opens, is verified in the mux package.
package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Signer holds a loaded Ed25519 private key and produces signed request headers.
type Signer struct {
	key      ed25519.PrivateKey
	tunnelID string
}

// NewSigner loads the private key from disk and returns a Signer.
func NewSigner(keyPath string, tunnelID string) (*Signer, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", keyPath)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not Ed25519")
	}

	return &Signer{key: key, tunnelID: tunnelID}, nil
}

// Headers returns the authentication headers for a request.
//
// A WebSocket handshake is an ordinary HTTP GET with an empty body, so the body
// hash is the hash of no bytes. The server signs the same constant.
//
// The tunnel id is not part of the signed payload, matching machine auth: the
// server canonicalizes the id before using it as the replay-nonce key, so
// excluding it here cannot open a second nonce space through case permutation.
func (s *Signer) Headers(method, path string, body []byte) map[string]string {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)

	bodyHash := sha256hex(body)

	// Signed payload: method:path:timestamp:nonce:bodyHash
	payload := fmt.Sprintf("%s:%s:%s:%s:%s", method, path, timestamp, nonce, bodyHash)
	sig := ed25519.Sign(s.key, []byte(payload))

	return map[string]string{
		"X-Tunnel-Id": s.tunnelID,
		"X-Timestamp": timestamp,
		"X-Nonce":     nonce,
		"X-Signature": base64.StdEncoding.EncodeToString(sig),
	}
}

func sha256hex(data []byte) string {
	h := sha256.Sum256(data)
	hex := make([]byte, 64)
	for i, b := range h {
		hex[i*2] = "0123456789abcdef"[b>>4]
		hex[i*2+1] = "0123456789abcdef"[b&0x0f]
	}
	return string(hex)
}
