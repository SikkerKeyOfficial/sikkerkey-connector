// Package tunnel dials SikkerKey and holds the connection open.
//
// The connector is always the dialer. SikkerKey asks, over a connection this
// host established, for a stream to a declared target.
package tunnel

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/SikkerKeyOfficial/sikkerkey-connector/internal/auth"
	"github.com/SikkerKeyOfficial/sikkerkey-connector/internal/config"
	"github.com/SikkerKeyOfficial/sikkerkey-connector/internal/mux"
)

// ConnectPath is the endpoint the connector dials. It is signed as part of the
// authentication payload, so a signature made for this path authorizes only
// this path.
const ConnectPath = "/v1/tunnel/connect"

const (
	// Backoff bounds. A tunnel-service deploy drops every connector at the same
	// instant, so retries are jittered rather than run in lockstep.
	backoffMin = 1 * time.Second
	backoffMax = 60 * time.Second

	// Handshake timeout. The far end verifies the signature with a round-trip to
	// the backend before completing the upgrade.
	handshakeTimeout = 20 * time.Second

	// Read deadline. The server pings every 30s, so approaching two missed pings
	// means the connection is dead even if the socket still looks open.
	readTimeout = 90 * time.Second
)

// Client holds one connector's connection to SikkerKey.
type Client struct {
	cfg    *config.Config
	signer *auth.Signer
	// Checks a stream-open request against the public key pinned at enrollment.
	// Built once, so a bad pinned key fails at startup rather than on first use.
	verifier *mux.Verifier
}

func New(cfg *config.Config) (*Client, error) {
	signer, err := auth.NewSigner(cfg.PrivateKeyPath, cfg.TunnelID)
	if err != nil {
		return nil, err
	}
	if cfg.TunnelSigningPublicKey == "" {
		return nil, fmt.Errorf("no SikkerKey signing key pinned; re-run the install command")
	}
	verifier, err := mux.NewVerifier(cfg.TunnelSigningPublicKey)
	if err != nil {
		return nil, fmt.Errorf("pinned SikkerKey key is unusable: %w", err)
	}
	return &Client{cfg: cfg, signer: signer, verifier: verifier}, nil
}

// Run dials and holds the connection, reconnecting until ctx is cancelled. It
// backs off and retries on every error rather than exiting.
func (c *Client) Run(ctx context.Context) error {
	backoff := backoffMin

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		start := time.Now()
		err := c.connectAndHold(ctx)

		if ctx.Err() != nil {
			return ctx.Err()
		}

		// A connection that lived a while before dropping resets the backoff, so
		// a long-lived tunnel does not inherit a ceiling from hours earlier.
		if time.Since(start) > 2*time.Minute {
			backoff = backoffMin
		}

		if err != nil {
			log.Printf("tunnel disconnected: %v", err)
		} else {
			log.Printf("tunnel closed by server")
		}

		wait := jitter(backoff)
		log.Printf("reconnecting in %s", wait.Round(time.Millisecond))

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}

		backoff *= 2
		if backoff > backoffMax {
			backoff = backoffMax
		}
	}
}

// connectAndHold performs one authenticated dial and blocks until it ends.
func (c *Client) connectAndHold(ctx context.Context) error {
	endpoint, err := c.endpointURL()
	if err != nil {
		return err
	}

	// The handshake is the authenticated request: the same signed headers a
	// machine sends, over the HTTP GET that upgrades to a WebSocket.
	headers := http.Header{}
	for k, v := range c.signer.Headers(http.MethodGet, ConnectPath, nil) {
		headers.Set(k, v)
	}

	dialer := &websocket.Dialer{
		HandshakeTimeout: handshakeTimeout,
		// Default TLS config, so the system trust store verifies the endpoint.
	}

	conn, resp, err := dialer.DialContext(ctx, endpoint, headers)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("handshake rejected (%s): %w", resp.Status, err)
		}
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	log.Printf("tunnel established to %s", c.cfg.TunnelURL)

	// The server pings; answering resets the read deadline. If pings stop, the
	// deadline fires and the read fails, which triggers a reconnect.
	conn.SetReadDeadline(time.Now().Add(readTimeout))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(readTimeout))
	})
	conn.SetPingHandler(func(appData string) error {
		if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			return err
		}
		return conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(10*time.Second))
	})

	// Close the socket when the context is cancelled so shutdown is immediate
	// rather than waiting on the read deadline.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()

	// gorilla/websocket forbids concurrent writers, and every open stream writes
	// through this one socket, so all sends serialize behind a mutex. The lock is
	// held only for the write itself.
	var writeMu sync.Mutex
	send := func(frame []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.WriteMessage(websocket.BinaryMessage, frame)
	}

	session := mux.NewSession(c.cfg.TunnelID, c.verifier, send)
	// Every stream holds a socket on this network; the connection ending makes
	// all of them dead.
	defer session.CloseAll()

	// Reading also keeps the connection alive and surfaces a close as an error.
	for {
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		switch msgType {
		case websocket.BinaryMessage:
			frame, parseErr := mux.Parse(payload)
			if parseErr != nil {
				log.Printf("mux: dropping malformed frame: %v", parseErr)
				continue
			}
			session.Handle(frame)
		case websocket.TextMessage:
			// Reserved; the protocol is binary.
		}
	}
}

// endpointURL converts the configured base URL to a ws:// or wss:// endpoint.
func (c *Client) endpointURL() (string, error) {
	base := strings.TrimRight(c.cfg.TunnelURL, "/")
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("invalid tunnel URL %q: %w", c.cfg.TunnelURL, err)
	}
	switch u.Scheme {
	case "https", "wss":
		u.Scheme = "wss"
	case "http", "ws":
		// Plaintext is for a local dev tunnel service only; production is wss.
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("unsupported tunnel URL scheme %q", u.Scheme)
	}
	u.Path = ConnectPath
	return u.String(), nil
}

// jitter spreads reconnects so a mass disconnect does not return as a
// synchronized burst. Full jitter: uniform over [d/2, d].
func jitter(d time.Duration) time.Duration {
	half := int64(d / 2)
	if half <= 0 {
		return d
	}
	n, err := rand.Int(rand.Reader, big.NewInt(half))
	if err != nil {
		return d
	}
	return time.Duration(half + n.Int64())
}
