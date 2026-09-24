// Cross-platform performance collectors (CPU, memory, network, disks,
// uptime, load) built on gopsutil, so Windows, Linux and macOS endpoints
// all report real data. Every function is best-effort: a platform that
// cannot serve a metric returns an empty value instead of an error that
// would block the rest of the report.
package endpoint

import (
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"

	agentv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/agent/v1"
)

// cpuOnce primes gopsutil's CPU-percent baseline: the first cpu.Percent(0)
// call has no previous reading and returns 0, so the collector samples it
// once at startup and every real reading afterwards is the utilization
// over the elapsed interval.
var cpuPrime sync.Once

// PrimeCPUSampling seeds the CPU utilization baseline. Call once before
// the first periodic collection.
func (c *Collector) PrimeCPUSampling() {
	cpuPrime.Do(func() {
		_, _ = cpu.Percent(0, false)
	})
}

// CPUPercentSinceLast returns system-wide CPU utilization (0-100) measured
// over the interval since the last call (first call returns ~0).
func (c *Collector) CPUPercentSinceLast() float64 {
	pcts, err := cpu.Percent(0, false)
	if err != nil || len(pcts) == 0 {
		return 0
	}
	return pcts[0]
}

// CPUInfo returns the CPU model name and physical core count (best-effort).
func (c *Collector) CPUInfo() (model string, cores int32) {
	infos, err := cpu.Info()
	if err != nil || len(infos) == 0 {
		return "", 0
	}
	model = infos[0].ModelName
	if cores32 := infos[0].Cores; cores32 > 0 {
		cores = int32(cores32)
	}
	return model, cores
}

// MemoryInfo returns total/used/available main memory in bytes.
func (c *Collector) MemoryInfo() (total, used, available uint64) {
	v, err := mem.VirtualMemory()
	if err != nil {
		return 0, 0, 0
	}
	return v.Total, v.Used, v.Available
}

// LoadAverages returns the 1/5/15-minute load averages; zeros on platforms
// without load averages (windows).
func (c *Collector) LoadAverages() (l1, l5, l15 float64) {
	avg, err := load.Avg()
	if err != nil || avg == nil {
		return 0, 0, 0
	}
	return avg.Load1, avg.Load5, avg.Load15
}

// UptimeSecs returns the host uptime in seconds.
func (c *Collector) UptimeSecs() uint64 {
	up, err := host.Uptime()
	if err != nil {
		return 0
	}
	return up
}

// KernelVersion returns the OS kernel version (best-effort).
func (c *Collector) KernelVersion() string {
	kv, err := host.KernelVersion()
	if err != nil {
		return ""
	}
	return kv
}

// NetInterfaces enumerates the host's NICs with MAC, MTU, addresses and
// up/down status for the authoritative inventory report.
func (c *Collector) NetInterfaces() []*agentv1.Iface {
	list, err := gnet.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]*agentv1.Iface, 0, len(list))
	for i := range list {
		iface := &agentv1.Iface{
			Name:   list[i].Name,
			Mac:    list[i].HardwareAddr,
			Mtu:    int32(list[i].MTU),
			Status: "down",
		}
		for _, f := range list[i].Flags {
			if f == "up" {
				iface.Status = "up"
				break
			}
		}
		for _, a := range list[i].Addrs {
			if addr := normalizeIfaceAddr(a.Addr); addr != "" {
				iface.Ips = append(iface.Ips, addr)
			}
		}
		out = append(out, iface)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}

// normalizeIfaceAddr reduces a system interface address to a plain IP
// literal: gopsutil reports addresses with a prefix length ("192.168.1.80/24",
// "fe80::1%eth0/64") and IPv6 zones carry a scope suffix — downstream
// consumers and the hub parse strict literals. Empty when the value is not
// a usable IP at all.
func normalizeIfaceAddr(addr string) string {
	if i := strings.IndexByte(addr, '/'); i >= 0 {
		addr = addr[:i]
	}
	if i := strings.LastIndexByte(addr, '%'); i >= 0 {
		addr = addr[:i]
	}
	addr = strings.TrimSpace(addr)
	if net.ParseIP(addr) == nil {
		return ""
	}
	return addr
}

// NetCounters snapshots per-NIC byte/packet counters. Rates are computed
// by the runtime against the previous snapshot.
func (c *Collector) NetCounters() map[string]*agentv1.IfaceMetrics {
	stats, err := gnet.IOCounters(true)
	if err != nil {
		return nil
	}
	out := make(map[string]*agentv1.IfaceMetrics, len(stats))
	for i := range stats {
		out[stats[i].Name] = &agentv1.IfaceMetrics{
			Name: stats[i].Name, RxBytes: stats[i].BytesRecv, TxBytes: stats[i].BytesSent,
			RxPackets: stats[i].PacketsRecv, TxPackets: stats[i].PacketsSent,
		}
	}
	return out
}

// ifaceRates computes the per-NIC byte rates over the interval between two
// counter snapshots. A NIC missing from the previous snapshot or whose
// counters went backwards (reset, hot-plug, container restart) yields zero
// rates for this sample — its counters are not comparable over the
// interval. The result is sorted by name for deterministic reports.
func ifaceRates(prev, cur map[string]*agentv1.IfaceMetrics, dt time.Duration) []*agentv1.IfaceMetrics {
	secs := dt.Seconds()
	names := make([]string, 0, len(cur))
	for name := range cur {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]*agentv1.IfaceMetrics, 0, len(names))
	for _, name := range names {
		c := cur[name]
		if prevC, ok := prev[name]; ok && secs > 0 &&
			c.RxBytes >= prevC.RxBytes && c.TxBytes >= prevC.TxBytes {
			c.RxBps = float64(c.RxBytes-prevC.RxBytes) / secs
			c.TxBps = float64(c.TxBytes-prevC.TxBytes) / secs
		}
		c.Name = name
		out = append(out, c)
	}
	return out
}

// DiskUsage enumerates mounted filesystems with capacity (bounded to 32
// mounts; virtual/pseudo filesystems are skipped by gopsutil's stat call
// failing on them).
func (c *Collector) DiskUsage() []*agentv1.Disk {
	parts, err := disk.Partitions(false)
	if err != nil {
		return nil
	}
	out := make([]*agentv1.Disk, 0, len(parts))
	for _, p := range parts {
		if len(out) >= 32 {
			break
		}
		u, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}
		out = append(out, &agentv1.Disk{
			Device: p.Device, Mountpoint: p.Mountpoint, Filesystem: p.Fstype,
			TotalBytes: u.Total, FreeBytes: u.Free,
		})
	}
	return out
}
