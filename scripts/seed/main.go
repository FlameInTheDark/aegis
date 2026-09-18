// Command seed prints instructions for the demo dataset (SQL-based, §139).
// The actual data lives in scripts/seed/demo.sql so it is reviewable and
// idempotent; applying it does not require a Go toolchain.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println(`Aegis demo dataset (spec §139)

Apply against a running stack:

  psql "$AEGIS_DATABASE_URL" -f scripts/seed/demo.sql
  clickhouse-client --queries-file scripts/seed/demo_clickhouse.sql

The demo data:
  - 1 organization ("Demo Organization", slug demo)
  - admin@aegis.local / aegis-demo-admin-2026 (argon2id hashed)
  - 3 sites (HQ, Datacenter, Branch) with VLAN networks
  - 13 assets (router, switch, firewall, servers, workstations, laptop,
    printer, camera, NAS, IoT, hypervisor) with observed services
  - 6 CVEs incl. KEV/EPSS enrichment and CPE matches
  - 3 findings with structured evidence, 4 detection rules, 2 matches
  - feed sources with license attribution

All rows are tagged demo/simulated and are never confused with production
scanner output.`)
	os.Exit(0)
}
