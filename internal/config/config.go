// Package config is the connector's on-disk identity and settings.
//
// Layout mirrors the CLI's (~/.sikkerkey, overridable via SIKKERKEY_HOME) so a
// host that already runs SikkerKey software keeps one place to look:
//
//	~/.sikkerkey/connector/config.json    0600
//	~/.sikkerkey/connector/connector.key  0600  (PKCS8 PEM, never transmitted)
//
// Enrollment writes both. The private key is generated here and only its public
// half is ever sent.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// Config is the connector's identity and where to reach SikkerKey.
type Config struct {
	// TunnelID is the tunnel this host was enrolled into. A tunnel binds to one
	// machine, so there is no separate connector id. Sent as a header and
	// resolved server-side, and not part of the signed payload.
	TunnelID string `json:"tunnelId"`

	// TunnelURL is the WebSocket endpoint, e.g. wss://tunnel.sikkerkey.com.
	// Stored rather than compiled in so a connector can be pointed at a
	// different deployment without a new binary.
	TunnelURL string `json:"tunnelUrl"`

	// PrivateKeyPath points at the PKCS8 PEM key, stored as a path rather than
	// as the key itself.
	PrivateKeyPath string `json:"privateKeyPath"`

	// TunnelSigningPublicKey is SikkerKey's per-tunnel public key, pinned at
	// enrollment. Every request arriving down this tunnel is verified against
	// it. Empty until enrollment supplies it.
	TunnelSigningPublicKey string `json:"tunnelSigningPublicKey,omitempty"`
}

// HomeDir resolves the home the connector's identity belongs to.
//
// Under sudo this is the invoking user's home, not root's. Install needs root
// to write a systemd unit, but the service runs as the invoking user, so
// resolving to /root would write the identity where the service cannot read it.
// os.UserHomeDir does not make this distinction.
func HomeDir() (string, error) {
	if h := os.Getenv("SIKKERKEY_HOME"); h != "" {
		return h, nil
	}
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && sudoUser != "root" {
		if u, err := user.Lookup(sudoUser); err == nil && u.HomeDir != "" {
			return u.HomeDir, nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return home, nil
}

// Dir returns the connector's config directory.
func Dir() (string, error) {
	home, err := HomeDir()
	if err != nil {
		return "", err
	}
	// SIKKERKEY_HOME names the .sikkerkey root directly; a real home contains it.
	if os.Getenv("SIKKERKEY_HOME") != "" {
		return filepath.Join(home, "connector"), nil
	}
	return filepath.Join(home, ".sikkerkey", "connector"), nil
}

// FixOwnership hands the written files to the invoking user when install ran
// under sudo. Without it the identity is owned by root and the service, which
// runs as that user, cannot read its own private key.
func FixOwnership(paths ...string) error {
	uidStr, gidStr := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")
	if uidStr == "" || gidStr == "" {
		return nil
	}
	uid, err := strconv.Atoi(uidStr)
	if err != nil {
		return nil
	}
	gid, err := strconv.Atoi(gidStr)
	if err != nil {
		return nil
	}
	for _, p := range paths {
		if err := os.Chown(p, uid, gid); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("set ownership on %s: %w", p, err)
		}
	}
	return nil
}

func Path() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// Load reads the connector config, returning a clear error when the connector
// has not been enrolled rather than a bare file-not-found.
func Load() (*Config, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no connector enrolled (expected %s). Run the install command from your SikkerKey dashboard", path)
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.TunnelID == "" || c.TunnelURL == "" || c.PrivateKeyPath == "" {
		return nil, fmt.Errorf("config at %s is incomplete", path)
	}
	return &c, nil
}

// Save writes the config 0600. The directory is created 0700, since it holds
// the private key alongside.
func Save(c *Config) error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	path, err := Path()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}
