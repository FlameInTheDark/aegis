# Test fixtures

All data in this directory is **synthetic** and safe to commit (:
the test suite never touches arbitrary real networks). Fixtures mirror the
real upstream schemas so adapter tests are faithful:

- `kev_sample.json` — CISA KEV catalog shape (2 entries)
- `epss_sample.json` — FIRST EPSS API shape (3 entries)
- `nvd_sample.json` — NVD API 2.0 shape (1 published CVE with CPE range + 1 rejected)
- `osv_sample.json` — OSV advisory shape (npm ecosystem, introduced/fixed range)
- `suricata_eve_sample.jsonl` — Suricata EVE JSON: alert/dns/http/tls/flow
- `zeek_conn_sample.jsonl`, `zeek_dns_sample.jsonl` — Zeek JSON logs
- `snort_alert_sample.json` — Snort 3 JSON alerts

Provenance: authored for this repository, not downloaded; field names follow
the upstream formats listed in docs/VULNERABILITY-FEEDS.md.
