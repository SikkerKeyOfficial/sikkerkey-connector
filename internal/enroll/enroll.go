// Package enroll claims a tunnel for this host.
//
// The keypair is generated here and only the public half is transmitted. The
// exchange is mutual: the response carries SikkerKey's own public key for this
// tunnel, which the connector pins and checks every inbound request against.
package enroll

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/SikkerKeyOfficial/sikkerkey-connector/internal/config"
)

// DefaultAPIURL is where enrollment is claimed. Only the tunnel endpoint is
// learned at runtime (it comes back in the response); this one is fixed because
// there is a single SikkerKey.
const DefaultAPIURL = "https://api.sikkerkey.com"

const enrollPath = "/v1/tunnel/enroll"

type request struct {
	Token     string `json:"token"`
	PublicKey string `json:"publicKey"`
	Hostname  string `json:"hostname,omitempty"`
}

type response struct {
	TunnelID               string `json:"tunnelId"`
	TunnelName             string `json:"tunnelName"`
	TunnelURL              string `json:"tunnelUrl"`
	TunnelSigningPublicKey string `json:"tunnelSigningPublicKey"`
}

type apiError struct {
	Error string `json:"error"`
}

// Result is what the caller reports to the operator after a successful claim.
type Result struct {
	TunnelID   string
	TunnelName string
	TunnelURL  string
	ConfigPath string
	KeyPath    string
}

// apiURL points a connector at a local backend during development.
func apiURL() string {
	if v := os.Getenv("SIKKERKEY_API_URL"); v != "" {
		return v
	}
	return DefaultAPIURL
}

// Run generates this host's identity, claims the tunnel, and writes both files.
// Nothing is written before the server accepts the claim.
func Run(token string) (*Result, error) {
	if token == "" {
		return nil, fmt.Errorf("no install token given")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	hostname, _ := os.Hostname()

	body, err := json.Marshal(request{
		Token:     token,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Hostname:  hostname,
	})
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodPost, apiURL()+enrollPath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reach SikkerKey: %w", err)
	}
	defer res.Body.Close()

	var decoded response
	if res.StatusCode < 200 || res.StatusCode > 299 {
		var e apiError
		if json.NewDecoder(res.Body).Decode(&e) == nil && e.Error != "" {
			return nil, fmt.Errorf("%s", e.Error)
		}
		return nil, fmt.Errorf("enrollment refused (%s)", res.Status)
	}
	if err := json.NewDecoder(res.Body).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if decoded.TunnelID == "" || decoded.TunnelURL == "" || decoded.TunnelSigningPublicKey == "" {
		return nil, fmt.Errorf("SikkerKey returned an incomplete enrollment")
	}

	dir, err := config.Dir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}

	keyPath := filepath.Join(dir, "connector.key")
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("encode private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("write %s: %w", keyPath, err)
	}

	cfg := &config.Config{
		TunnelID:               decoded.TunnelID,
		TunnelURL:              decoded.TunnelURL,
		PrivateKeyPath:         keyPath,
		TunnelSigningPublicKey: decoded.TunnelSigningPublicKey,
	}
	if err := config.Save(cfg); err != nil {
		return nil, err
	}

	cfgPath, _ := config.Path()

	// Install runs under sudo, but the service runs as the invoking user, so the
	// files are handed to them.
	if err := config.FixOwnership(filepath.Dir(dir), dir, keyPath, cfgPath); err != nil {
		return nil, err
	}

	return &Result{
		TunnelID:   decoded.TunnelID,
		TunnelName: decoded.TunnelName,
		TunnelURL:  decoded.TunnelURL,
		ConfigPath: cfgPath,
		KeyPath:    keyPath,
	}, nil
}
