// Package service registers the connector with the host's init system, as a
// systemd unit on Linux and a launchd agent on macOS.
package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/SikkerKeyOfficial/sikkerkey-connector/internal/config"
)

const (
	// One connector per host, so the unit is named for the product rather than
	// for a tunnel id. A second install replaces the first.
	systemdUnit  = "sikkerkey-connector"
	launchdLabel = "com.sikkerkey.connector"

	// Where the service runs the binary from. Fixed, so the unit does not point
	// at whatever directory the install was run from.
	installPath = "/usr/local/bin/sikkerkey-connector"
)

// Binary is the path the service unit points at.
func Binary() string { return installPath }

// ensureBinaryInstalled copies the running executable to [installPath].
//
// It stages a temp file alongside the destination and renames over it. Writing
// in place returns ETXTBSY while an older connector is still running.
func ensureBinaryInstalled() error {
	src, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve running binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(src); err == nil {
		src = resolved
	}

	// Already running from the install location.
	if dst, err := filepath.EvalSymlinks(installPath); err == nil && dst == src {
		return nil
	}

	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	if err := os.MkdirAll(filepath.Dir(installPath), 0755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(installPath), err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(installPath), ".sikkerkey-connector-*")
	if err != nil {
		return fmt.Errorf("stage binary in %s: %w (try again with sudo)", filepath.Dir(installPath), err)
	}
	staged := tmp.Name()
	defer os.Remove(staged) // no-op once the rename succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write staged binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close staged binary: %w", err)
	}
	if err := os.Chmod(staged, 0755); err != nil {
		return fmt.Errorf("chmod staged binary: %w", err)
	}
	if err := os.Rename(staged, installPath); err != nil {
		return fmt.Errorf("install to %s: %w (try again with sudo)", installPath, err)
	}

	fmt.Printf("Binary installed to %s\n", installPath)
	return nil
}

// currentUser prefers the user who invoked sudo, so the service runs as them
// and reads the identity from their home.
func currentUser() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "root"
}

// currentHome resolves the home the identity was written into. A systemd
// service has no HOME unless given one, so this value is stamped into the unit
// and must match the answer enrollment used.
func currentHome() string {
	h, err := config.HomeDir()
	if err != nil {
		return "/root"
	}
	return h
}

// Preflight reports whether Install would succeed, without changing anything.
// It runs before enrollment, which spends a single-use token.
func Preflight() error {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("systemctl"); err != nil {
			return fmt.Errorf("systemctl not found. Enroll manually with 'install' and run 'sikkerkey-connector run' under your own supervisor")
		}
		if err := probeWritable(filepath.Dir(installPath)); err != nil {
			return err
		}
		return probeWritable("/etc/systemd/system")
	case "darwin":
		if _, err := exec.LookPath("launchctl"); err != nil {
			return fmt.Errorf("launchctl not found")
		}
		home, err := config.HomeDir()
		if err != nil {
			return fmt.Errorf("resolve home directory: %w", err)
		}
		dir := filepath.Join(home, "Library", "LaunchAgents")
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		if err := probeWritable(filepath.Dir(installPath)); err != nil {
			return err
		}
		return probeWritable(dir)
	default:
		return fmt.Errorf("automatic service install is not supported on %s yet", runtime.GOOS)
	}
}

// probeWritable creates and removes a file. euid alone misses read-only
// mounts, and stat permissions miss ACLs.
func probeWritable(dir string) error {
	probe := filepath.Join(dir, ".sikkerkey-connector-probe")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0644)
	if err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("cannot write to %s. Re-run with sudo", dir)
		}
		return fmt.Errorf("cannot write to %s: %w", dir, err)
	}
	f.Close()
	os.Remove(probe)
	return nil
}

// Install places the binary at [installPath], then registers and starts the
// service.
func Install() error {
	switch runtime.GOOS {
	case "linux":
		if err := ensureBinaryInstalled(); err != nil {
			return err
		}
		return installSystemd()
	case "darwin":
		if err := ensureBinaryInstalled(); err != nil {
			return err
		}
		return installLaunchd()
	default:
		return fmt.Errorf(
			"automatic service install is not supported on %s yet. The tunnel is enrolled; run 'sikkerkey-connector run' to hold it open",
			runtime.GOOS,
		)
	}
}

// Uninstall stops and removes the service. The identity and the binary at
// [installPath] are left in place, so the tunnel can be started again without
// re-enrolling.
func Uninstall() error {
	switch runtime.GOOS {
	case "linux":
		return uninstallSystemd()
	case "darwin":
		return uninstallLaunchd()
	default:
		return fmt.Errorf("no service was installed on %s", runtime.GOOS)
	}
}

// ── systemd ──

func installSystemd() error {
	user := currentUser()
	home := currentHome()

	unit := fmt.Sprintf(`[Unit]
Description=SikkerKey Connector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=%s
ExecStart=%s run
Restart=always
RestartSec=10
Environment=HOME=%s
WorkingDirectory=%s

[Install]
WantedBy=multi-user.target
`, user, Binary(), home, home)

	path := fmt.Sprintf("/etc/systemd/system/%s.service", systemdUnit)
	if err := os.WriteFile(path, []byte(unit), 0644); err != nil {
		return fmt.Errorf("write %s: %w (try again with sudo)", path, err)
	}
	fmt.Printf("Service written to %s\n", path)

	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if err := exec.Command("systemctl", "enable", "--now", systemdUnit).Run(); err != nil {
		return fmt.Errorf("systemctl enable: %w", err)
	}

	fmt.Println()
	fmt.Printf("  Status: sudo systemctl status %s\n", systemdUnit)
	fmt.Printf("  Logs:   sudo journalctl -u %s -f\n", systemdUnit)
	fmt.Printf("  Stop:   sudo systemctl stop %s\n", systemdUnit)
	return nil
}

func uninstallSystemd() error {
	_ = exec.Command("systemctl", "disable", "--now", systemdUnit).Run()
	path := fmt.Sprintf("/etc/systemd/system/%s.service", systemdUnit)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w (try again with sudo)", path, err)
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	fmt.Println("Service stopped and removed.")
	return nil
}

// ── launchd ──

func launchdPlistPath() (string, error) {
	home, err := config.HomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist"), nil
}

func installLaunchd() error {
	home := currentHome()
	logPath := filepath.Join(home, ".sikkerkey", "connector", "connector.log")

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>%s</string>
    <key>StandardErrorPath</key>
    <string>%s</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>HOME</key>
        <string>%s</string>
    </dict>
</dict>
</plist>
`, launchdLabel, Binary(), logPath, logPath, home)

	path, err := launchdPlistPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create LaunchAgents directory: %w", err)
	}
	// A reinstall must replace a running agent, not stack on top of it.
	_ = exec.Command("launchctl", "unload", path).Run()

	if err := os.WriteFile(path, []byte(plist), 0644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Printf("Service written to %s\n", path)

	if err := exec.Command("launchctl", "load", path).Run(); err != nil {
		return fmt.Errorf("launchctl load: %w", err)
	}

	fmt.Println()
	fmt.Printf("  Logs: tail -f %s\n", logPath)
	fmt.Printf("  Stop: launchctl unload %s\n", path)
	return nil
}

func uninstallLaunchd() error {
	path, err := launchdPlistPath()
	if err != nil {
		return err
	}
	_ = exec.Command("launchctl", "unload", path).Run()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	fmt.Println("Service stopped and removed.")
	return nil
}
