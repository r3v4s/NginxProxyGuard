package model

import (
	"fmt"
	"strings"
	"time"
)

// AccessList represents a reusable access control list
type AccessList struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	SatisfyAny  bool             `json:"satisfy_any"` // true = any rule match, false = all must match
	PassAuth    bool             `json:"pass_auth"`   // Allow authenticated users to bypass
	Items       []AccessListItem `json:"items,omitempty"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
}

// AccessListItem represents a single allow/deny rule
type AccessListItem struct {
	ID           string    `json:"id"`
	AccessListID string    `json:"access_list_id"`
	Directive    string    `json:"directive"` // "allow" or "deny"
	Address      string    `json:"address"`   // IP, CIDR, or "all"
	Description  string    `json:"description,omitempty"`
	SortOrder    int       `json:"sort_order"`
	CreatedAt    time.Time `json:"created_at"`

	// Hostname is set on a domain row (#320). Such a row is stored as
	// (deny, all, hostname), which every version without domain rows renders
	// as "deny all": closed. Only the API DTO shows it as an allow row with
	// kind "hostname"; code that does not know Hostname keeps the row closed.
	Hostname string `json:"-"`
}

// CreateAccessListRequest is the request to create an access list
type CreateAccessListRequest struct {
	Name        string                       `json:"name" validate:"required,min=1,max=255"`
	Description string                       `json:"description,omitempty"`
	SatisfyAny  *bool                        `json:"satisfy_any,omitempty"`
	PassAuth    *bool                        `json:"pass_auth,omitempty"`
	Items       []CreateAccessListItemRequest `json:"items,omitempty"`
}

// CreateAccessListItemRequest is the request to create an access list item
type CreateAccessListItemRequest struct {
	Directive   string `json:"directive" validate:"required,oneof=allow deny"`
	Address     string `json:"address" validate:"required"`
	Description string `json:"description,omitempty"`
	SortOrder   int    `json:"sort_order,omitempty"`

	// Hostname makes the item a domain rule (#320): the repository stores it
	// as the placeholder (deny, all, hostname) whatever Directive and Address
	// say. It is never read from a request body; only server code sets it.
	Hostname string `json:"-"`
}

// UpdateAccessListRequest is the request to update an access list
type UpdateAccessListRequest struct {
	Name        *string                       `json:"name,omitempty"`
	Description *string                       `json:"description,omitempty"`
	SatisfyAny  *bool                         `json:"satisfy_any,omitempty"`
	PassAuth    *bool                         `json:"pass_auth,omitempty"`
	Items       []CreateAccessListItemRequest `json:"items,omitempty"`
}

// AccessListListResponse is the response for listing access lists
type AccessListListResponse struct {
	Data       []AccessList `json:"data"`
	Total      int          `json:"total"`
	Page       int          `json:"page"`
	PerPage    int          `json:"per_page"`
	TotalPages int          `json:"total_pages"`
}

// An access list is written into the nginx config of every proxy host that
// uses it: each rule as an "allow" or "deny" line, the list's name and each
// rule's description as "#" comments.

// accessListRuleMaxDescription bounds a rule description, which sits in a "#"
// comment after its rule: nginx refuses a comment line of 4 KB or more, and
// the config generator writes at most 1 KB of one.
const accessListRuleMaxDescription = 1000

// IsAccessListDirective reports whether d is a directive an access list rule
// can use.
func IsAccessListDirective(d string) bool {
	return d == "allow" || d == "deny"
}

// IsAccessListAddress reports whether a is an address nginx's allow and deny
// directives take: an IP address, a CIDR range, or "all".
func IsAccessListAddress(a string) bool {
	return a == "all" || IsIPOrCIDR(a)
}

// ValidateCreateAccessListRequest checks what a new access list writes into
// the config. Whether the name is present and short enough is the handler's
// check.
func ValidateCreateAccessListRequest(req *CreateAccessListRequest) error {
	if err := ValidateSingleLine("name", req.Name, 0); err != nil {
		return err
	}
	if err := ValidateSingleLine("description", req.Description, 0); err != nil {
		return err
	}
	return validateAccessListItems(req.Items)
}

// ValidateUpdateAccessListRequest checks the fields an update sends.
func ValidateUpdateAccessListRequest(req *UpdateAccessListRequest) error {
	if req.Name != nil {
		if err := ValidateSingleLine("name", *req.Name, 0); err != nil {
			return err
		}
	}
	if req.Description != nil {
		if err := ValidateSingleLine("description", *req.Description, 0); err != nil {
			return err
		}
	}
	return validateAccessListItems(req.Items)
}

// validateAccessListItems checks each rule. An address is trimmed of
// surrounding whitespace first and saved that way.
func validateAccessListItems(items []CreateAccessListItemRequest) error {
	for i := range items {
		item := &items[i]
		item.Address = strings.TrimSpace(item.Address)
		if !IsAccessListDirective(item.Directive) {
			return fmt.Errorf("%w: items[%d].directive must be allow or deny", ErrInvalidInput, i)
		}
		if !IsAccessListAddress(item.Address) {
			return fmt.Errorf("%w: items[%d].address %q must be an IP address, a CIDR range or all", ErrInvalidInput, i, item.Address)
		}
		if err := ValidateSingleLine(fmt.Sprintf("items[%d].description", i), item.Description, accessListRuleMaxDescription); err != nil {
			return err
		}
	}
	return nil
}
