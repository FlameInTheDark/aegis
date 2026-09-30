-- F4 (SSO first slice): one OIDC provider per organization. The client
-- secret follows the plaintext-secret convention of this codebase and is
-- never serialized. Owner is not assignable through group claims.
CREATE TABLE IF NOT EXISTS org_sso (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    issuer          TEXT NOT NULL,
    client_id       TEXT NOT NULL,
    client_secret   TEXT NOT NULL DEFAULT '',
    groups_claim    TEXT NOT NULL DEFAULT 'groups',
    role_mappings   JSONB NOT NULL DEFAULT '{}'::jsonb,
    default_role    TEXT NOT NULL DEFAULT 'viewer',
    allow_jit       BOOLEAN NOT NULL DEFAULT true,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
