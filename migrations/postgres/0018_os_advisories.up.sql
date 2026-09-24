-- 0018: OS advisory data plane (vuls adaptation, docs/VULS_ADAPTATION.md §5
-- phase 2). One row per (distro release, package, CVE, advisory) carrying
-- the distro's fixed version — the deterministic high-confidence detection
-- source for OS packages, equivalent to vuls' OVAL/gost plane.

CREATE TABLE os_advisories (
    id              UUID PRIMARY KEY,
    family          TEXT NOT NULL,             -- canonical family (debian, ubuntu, alpine, rhel, ...)
    release         TEXT NOT NULL,             -- advisory release key ("12", "22.04", "9", "3.18")
    package_name    TEXT NOT NULL,             -- binary package name as dpkg/rpm/apk report it
    source_package  TEXT,                      -- source package when OVAL keys it differently
    fixed_version   TEXT,                      -- first fixed version in distro packaging (NULL when unfixed)
    not_fixed_yet   BOOLEAN NOT NULL DEFAULT false,
    cve_id          TEXT NOT NULL,
    advisory_id     TEXT NOT NULL,             -- DSA-5710-1 / USN-6201-1 / RHSA-2023:12345 / ALSA-...
    advisory_url    TEXT,
    severity        TEXT,                      -- distro-declared severity, informational only
    published_at    TIMESTAMPTZ,
    source          TEXT NOT NULL,             -- oval | seed
    source_version  TEXT,
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The lookup aegis performs per installed package during correlation.
CREATE INDEX idx_os_adv_lookup ON os_advisories(family, release, package_name);
-- CVE-centric reads (report enrichment, ad hoc queries).
CREATE INDEX idx_os_adv_cve ON os_advisories(cve_id);
-- Idempotent ingest: one row per (release, package, CVE, advisory).
CREATE UNIQUE INDEX uq_os_adv ON os_advisories(family, release, package_name, cve_id, advisory_id);
