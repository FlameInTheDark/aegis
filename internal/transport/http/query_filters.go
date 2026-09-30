package httpx

import (
	"github.com/google/uuid"
)

// uuidFilterParam normalizes an optional UUID query parameter that backs an
// "all | specific id" console selector (site scope, asset scope, ...).
//
// The console's scope selector uses the literal "all" as its sentinel and
// empty means unfiltered. Anything else must parse as a UUID: a malformed
// value is a client error (400), never a database cast failure surfaced as
// a 500. Reported as GET /changes?site_id=all → internal_error before the
// helper existed; every Postgres list endpoint that feeds a uuid column
// from a query parameter now routes through it.
func uuidFilterParam(raw string) (string, error) {
	if raw == "" || raw == "all" {
		return "", nil
	}
	if uuid.Validate(raw) != nil {
		return "", BadRequest("must be a UUID or 'all'")
	}
	return raw, nil
}
