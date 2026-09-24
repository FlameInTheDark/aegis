package scanner

// EnsureGatewayLink guarantees a traced host lands CONNECTED in the site
// graph. A successful traceroute to a directly connected (same-subnet) host
// is a single hop — the target answers at TTL 1, no router in between — and
// a one-node path cannot produce an edge: the orchestrator chains
// hop[i] -> hop[i+1], so every LAN topology scan rendered its hosts as
// isolated dots even though every trace "worked". The default gateway still
// carries the traffic at L3, so a [gateway, target] path is synthesized;
// callers re-label the method ("gateway-l2") and lower the confidence
// because the link is inferred from adjacency, not observed hop-by-hop.
//
// Everything else passes through unchanged: real multi-hop routes, partial
// routes whose single responsive hop is NOT the target (the orchestrator
// already links the deepest reachable hop to the asset), the gateway itself
// (no parent to invent) and non-IPv4 targets.
func EnsureGatewayLink(hops []Hop, target string) []Hop {
	if len(hops) != 1 || hops[0].IP != target {
		return hops
	}
	gw := GatewayOf(target)
	if gw == "" || gw == target {
		return hops
	}
	return []Hop{
		{TTL: 1, IP: gw},
		{TTL: 2, IP: target, Hostname: hops[0].Hostname, RTTms: hops[0].RTTms},
	}
}
