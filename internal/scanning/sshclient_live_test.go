package scanning

// Live-handshake tests: a minimal in-process sshd (x/crypto/ssh
// ServerConfig) so the real client/server negotiation is exercised, not
// just authMethods bookkeeping. Covers the field regression where a
// configured-but-unusable key file made login+password scanning fail with
// "ssh key: ssh: no key found" before the password was ever offered.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const stubSSHPass = "s3cret-pw"

// startStubSSHServer runs a minimal sshd for the test. Each bool selects
// which auth the server advertises; both credentials equal stubSSHPass.
func startStubSSHServer(t *testing.T, acceptPassword, acceptKbd bool) (host string, port int) {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{}
	if acceptPassword {
		cfg.PasswordCallback = func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) == stubSSHPass {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("password rejected")
		}
	}
	if acceptKbd {
		cfg.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := client("", "auth", []string{"Password:"}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(answers) == 1 && answers[0] == stubSSHPass {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("keyboard-interactive rejected")
		}
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveStubSSHConn(c, cfg)
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, err = strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func serveStubSSHConn(c net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, chReqs, _ := newCh.Accept()
		go func() {
			defer ch.Close()
			for r := range chReqs {
				if r.Type == "exec" {
					_ = r.Reply(true, nil)
					_, _ = ch.Write([]byte("ok"))
					// sess.Output blocks until an exit-status request arrives.
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					return
				}
				_ = r.Reply(false, nil)
			}
		}()
	}
}

func runStubCollectCmd(t *testing.T, c *SSHClient, host string, port int) string {
	t.Helper()
	out, err := c.Run(context.Background(), SSHHostConfig{Host: host, Port: port}, "true")
	if err != nil {
		t.Fatalf("ssh Run: %v", err)
	}
	return strings.TrimSpace(out)
}

func TestSSHClientPasswordAuthLive(t *testing.T) {
	host, port := startStubSSHServer(t, true, false)
	c := &SSHClient{User: "scan", Password: stubSSHPass, Timeout: 5 * time.Second, InsecureHostKey: true}
	if got := runStubCollectCmd(t, c, host, port); got != "ok" {
		t.Fatalf("want exec output %q, got %q", "ok", got)
	}
}

// Hardened sshd: plain "password" disabled, keyboard-interactive (PAM) only.
func TestSSHClientKeyboardInteractiveOnlyServer(t *testing.T) {
	host, port := startStubSSHServer(t, false, true)
	c := &SSHClient{User: "scan", Password: stubSSHPass, Timeout: 5 * time.Second, InsecureHostKey: true}
	if got := runStubCollectCmd(t, c, host, port); got != "ok" {
		t.Fatalf("keyboard-interactive auth must work: got %q", got)
	}
}

// THE regression: garbage KeyPEM (e.g. a *.pub file) + valid password must
// still authenticate — the broken key is skipped, not fatal.
func TestSSHClientBrokenKeyWithPasswordStillAuths(t *testing.T) {
	host, port := startStubSSHServer(t, true, true)
	c := &SSHClient{User: "scan", Password: stubSSHPass, KeyPEM: []byte("ssh: this used to kill the whole connection"),
		Timeout: 5 * time.Second, InsecureHostKey: true}
	if got := runStubCollectCmd(t, c, host, port); got != "ok" {
		t.Fatalf("broken key must not block password auth: got %q", got)
	}
}

func TestSSHClientWrongPasswordFails(t *testing.T) {
	host, port := startStubSSHServer(t, true, true)
	c := &SSHClient{User: "scan", Password: "totally-wrong", Timeout: 5 * time.Second, InsecureHostKey: true}
	if _, err := c.Run(context.Background(), SSHHostConfig{Host: host, Port: port}, "true"); err == nil {
		t.Fatal("wrong password must fail")
	}
}

func TestSSHClientBrokenKeyWithoutPasswordFails(t *testing.T) {
	host, port := startStubSSHServer(t, true, true)
	c := &SSHClient{User: "scan", KeyPEM: []byte("garbage"), KeyPath: "/keys/id_rsa",
		Timeout: 5 * time.Second, InsecureHostKey: true}
	_, err := c.Run(context.Background(), SSHHostConfig{Host: host, Port: port}, "true")
	if err == nil || !strings.Contains(err.Error(), "/keys/id_rsa") {
		t.Fatalf("broken key without fallback must fail naming the file, got: %v", err)
	}
}
