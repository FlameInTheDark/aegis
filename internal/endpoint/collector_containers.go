//go:build linux

package endpoint

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	agentv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/agent/v1"
)

// Container workload inventory (F9 first slice): at collection level
// "full", a read-only list of containers via the local Docker-compatible
// runtime socket when the agent is permitted to read it. Containers land
// as software rows (source='docker') so matching stays on the one
// inventory path; promoting them to child assets waits for the asset
// model to grow a real parent relationship.

const dockerSocketPath = "/var/run/docker.sock"

// dockerContainer mirrors GET /containers/json.
type dockerContainer struct {
	Names   []string `json:"Names"`
	Image   string   `json:"Image"`
	ImageID string   `json:"ImageID"`
	State   string   `json:"State"`
}

// dockerSocketPathFor resolves the socket: DOCKER_HOST (unix:// or empty
// meaning default) wins, then the default path. A TCP DOCKER_HOST is not
// honored from the agent — remote container enumeration is out of scope.
func dockerSocketPathFor(dockerHost string) string {
	if dockerHost != "" {
		if p, ok := strings.CutPrefix(dockerHost, "unix://"); ok {
			return p
		}
	}
	return dockerSocketPath
}

// parseDockerContainers maps the API response into inventory packages.
// Pure function: unit-tested with fixture payloads.
func parseDockerContainers(data []byte) []agentv1.SoftwareReport_Package {
	var cs []dockerContainer
	if err := json.Unmarshal(data, &cs); err != nil {
		return nil
	}
	out := make([]agentv1.SoftwareReport_Package, 0, len(cs))
	for _, c := range cs {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		if name == "" {
			name = c.Image
		}
		if name == "" {
			continue
		}
		out = append(out, agentv1.SoftwareReport_Package{
			Name:      "docker/" + name,
			Version:   c.ImageID,
			Vendor:    "docker",
			Ecosystem: "",
			Source:    "container",
		})
	}
	return out
}

// Containers lists running containers, or nil when the socket is absent
// or unreadable. Absence is silent — an agent without runtime access is a
// normal deployment, not an error.
func (c *Collector) Containers() []agentv1.SoftwareReport_Package {
	if c.Cfg.CollectionLevel != "full" {
		return nil
	}
	sock := dockerSocketPathFor(os.Getenv("DOCKER_HOST"))
	st, err := os.Stat(sock)
	if err != nil || st.Mode()&os.ModeSocket == 0 {
		return nil
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", sock, 3*time.Second)
			},
		},
	}
	resp, err := client.Get("http://docker/v1.24/containers/json")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil || len(buf) > 8<<20 {
			break
		}
	}
	return parseDockerContainers(buf)
}
