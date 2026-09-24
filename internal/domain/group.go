package domain

import "time"

// AssetGroupKind labels the intent of an analyst-defined asset group. The
// UI uses it to suggest icons/colors; the backend treats it as opaque.
type AssetGroupKind string

const (
	GroupKindLocation AssetGroupKind = "location"
	GroupKindFunction AssetGroupKind = "function"
	GroupKindOwner    AssetGroupKind = "owner"
	GroupKindCustom   AssetGroupKind = "custom"
)

// AssetGroup is a user-curated set of assets ("Room 1", "IoT devices",
// "PCI scope"). Membership lives in asset_group_members; one asset can
// belong to any number of groups and the UI renders the first as a chip.
type AssetGroup struct {
	ID          string         `json:"id"`
	OrgID       string         `json:"organization_id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Color       string         `json:"color"` // palette key resolved client-side
	Icon        string         `json:"icon"`  // icon key resolved client-side
	Kind        AssetGroupKind `json:"kind"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// AssetGroupWithMembers is the serialized list form: the group plus the ids
// of its member assets. Members are returned inline because every asset row
// in the UI needs its chip badges — one endpoint serves the whole store.
type AssetGroupWithMembers struct {
	AssetGroup
	AssetIDs []string `json:"asset_ids"`
}
