package model

import (
	"fmt"
	"strings"
	"time"
)

// GeoRestriction represents geo-blocking settings for a proxy host
type GeoRestriction struct {
	ID              string    `json:"id"`
	ProxyHostID     string    `json:"proxy_host_id"`
	Mode            string    `json:"mode"`              // "whitelist" or "blacklist"
	Countries       []string  `json:"countries"`         // ISO 3166-1 alpha-2 country codes
	AllowedIPs      []string  `json:"allowed_ips"`       // IPs/CIDRs that bypass geo restrictions
	AllowPrivateIPs bool      `json:"allow_private_ips"` // Allow private IP ranges (10.x, 172.16-31.x, 192.168.x)
	AllowSearchBots bool      `json:"allow_search_bots"` // Allow search engine bots (Googlebot, Bingbot, etc.)
	Enabled         bool      `json:"enabled"`
	ChallengeMode   bool      `json:"challenge_mode"`    // Show CAPTCHA instead of blocking
	DisableGlobal   bool      `json:"disable_global"`    // Host opts out of the global geo default (3-state: inherit/override/disable)
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`

	// AllowedHostnames are domain names (#320) whose addresses bypass the
	// restriction like AllowedIPs. Never null.
	AllowedHostnames []string `json:"allowed_hostnames"`
	// AllowedDNS is what a host config renders of the names: each with the
	// scope of the list it came from, the host's or the global one
	// (resolveGeo). Set for the render only, never stored, cached or sent.
	// The host's WAF file never gets them (only AllowedIPs).
	AllowedDNS []DNSRef `json:"-"`
}

// GlobalGeoRestriction is the singleton global default inherited by hosts that
// neither override (own enabled geo) nor disable (disable_global=true).
type GlobalGeoRestriction struct {
	ID              string    `json:"id"`
	Enabled         bool      `json:"enabled"`
	Mode            string    `json:"mode"`
	Countries       []string  `json:"countries"`
	AllowedIPs      []string  `json:"allowed_ips"`
	AllowPrivateIPs bool      `json:"allow_private_ips"`
	AllowSearchBots bool      `json:"allow_search_bots"`
	ChallengeMode   bool      `json:"challenge_mode"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`

	// AllowedHostnames are domain names (#320) whose addresses bypass the
	// restriction like AllowedIPs. Never null.
	AllowedHostnames []string `json:"allowed_hostnames"`
}

// UpdateGlobalGeoRestrictionRequest is a partial update (pointer fields) for the
// global geo singleton.
type UpdateGlobalGeoRestrictionRequest struct {
	Enabled         *bool    `json:"enabled,omitempty"`
	Mode            *string  `json:"mode,omitempty" validate:"omitempty,oneof=whitelist blacklist"`
	Countries       []string `json:"countries,omitempty"`
	AllowedIPs      []string `json:"allowed_ips,omitempty"`
	AllowPrivateIPs *bool    `json:"allow_private_ips,omitempty"`
	AllowSearchBots *bool    `json:"allow_search_bots,omitempty"`
	ChallengeMode   *bool    `json:"challenge_mode,omitempty"`

	// AllowedHostnames replaces the stored names; nil (the field left out)
	// keeps them and [] clears them.
	AllowedHostnames *[]string `json:"allowed_hostnames,omitempty"`
}

// CreateGeoRestrictionRequest is the request to create/update geo restriction
type CreateGeoRestrictionRequest struct {
	Mode            string   `json:"mode" validate:"required,oneof=whitelist blacklist"`
	Countries       []string `json:"countries" validate:"required,min=1"`
	AllowedIPs      []string `json:"allowed_ips,omitempty"`       // IPs/CIDRs that bypass geo restrictions
	AllowPrivateIPs *bool    `json:"allow_private_ips,omitempty"` // Allow private IP ranges
	AllowSearchBots *bool    `json:"allow_search_bots,omitempty"` // Allow search engine bots
	Enabled         *bool    `json:"enabled,omitempty"`
	ChallengeMode   *bool    `json:"challenge_mode,omitempty"`    // Show CAPTCHA instead of blocking
	DisableGlobal   *bool    `json:"disable_global,omitempty"`    // Opt out of global geo default

	// AllowedHostnames replaces the stored names. Unlike the other fields,
	// which a save always writes, nil (the field left out) keeps them, so a
	// client that does not know the field cannot clear them; [] clears
	// them.
	AllowedHostnames *[]string `json:"allowed_hostnames,omitempty"`
}

// UpdateGeoRestrictionRequest is the request to update geo restriction
type UpdateGeoRestrictionRequest struct {
	Mode            *string  `json:"mode,omitempty"`
	Countries       []string `json:"countries,omitempty"`
	AllowedIPs      []string `json:"allowed_ips,omitempty"`       // IPs/CIDRs that bypass geo restrictions
	AllowPrivateIPs *bool    `json:"allow_private_ips,omitempty"` // Allow private IP ranges
	AllowSearchBots *bool    `json:"allow_search_bots,omitempty"` // Allow search engine bots
	Enabled         *bool    `json:"enabled,omitempty"`
	ChallengeMode   *bool    `json:"challenge_mode,omitempty"`    // Show CAPTCHA instead of blocking
	DisableGlobal   *bool    `json:"disable_global,omitempty"`    // Opt out of global geo default

	// AllowedHostnames replaces the stored names; nil (the field left out)
	// keeps them and [] clears them.
	AllowedHostnames *[]string `json:"allowed_hostnames,omitempty"`
}

// CommonCountryCodes contains all ISO 3166-1 alpha-2 country codes (249 entries)
var CommonCountryCodes = map[string]string{
	"AD": "Andorra",
	"AE": "United Arab Emirates",
	"AF": "Afghanistan",
	"AG": "Antigua and Barbuda",
	"AI": "Anguilla",
	"AL": "Albania",
	"AM": "Armenia",
	"AO": "Angola",
	"AQ": "Antarctica",
	"AR": "Argentina",
	"AS": "American Samoa",
	"AT": "Austria",
	"AU": "Australia",
	"AW": "Aruba",
	"AX": "Åland Islands",
	"AZ": "Azerbaijan",
	"BA": "Bosnia and Herzegovina",
	"BB": "Barbados",
	"BD": "Bangladesh",
	"BE": "Belgium",
	"BF": "Burkina Faso",
	"BG": "Bulgaria",
	"BH": "Bahrain",
	"BI": "Burundi",
	"BJ": "Benin",
	"BL": "Saint Barthélemy",
	"BM": "Bermuda",
	"BN": "Brunei",
	"BO": "Bolivia",
	"BQ": "Bonaire, Sint Eustatius and Saba",
	"BR": "Brazil",
	"BS": "Bahamas",
	"BT": "Bhutan",
	"BV": "Bouvet Island",
	"BW": "Botswana",
	"BY": "Belarus",
	"BZ": "Belize",
	"CA": "Canada",
	"CC": "Cocos (Keeling) Islands",
	"CD": "Congo (DRC)",
	"CF": "Central African Republic",
	"CG": "Congo",
	"CH": "Switzerland",
	"CI": "Côte d'Ivoire",
	"CK": "Cook Islands",
	"CL": "Chile",
	"CM": "Cameroon",
	"CN": "China",
	"CO": "Colombia",
	"CR": "Costa Rica",
	"CU": "Cuba",
	"CV": "Cabo Verde",
	"CW": "Curaçao",
	"CX": "Christmas Island",
	"CY": "Cyprus",
	"CZ": "Czechia",
	"DE": "Germany",
	"DJ": "Djibouti",
	"DK": "Denmark",
	"DM": "Dominica",
	"DO": "Dominican Republic",
	"DZ": "Algeria",
	"EC": "Ecuador",
	"EE": "Estonia",
	"EG": "Egypt",
	"EH": "Western Sahara",
	"ER": "Eritrea",
	"ES": "Spain",
	"ET": "Ethiopia",
	"FI": "Finland",
	"FJ": "Fiji",
	"FK": "Falkland Islands",
	"FM": "Micronesia",
	"FO": "Faroe Islands",
	"FR": "France",
	"GA": "Gabon",
	"GB": "United Kingdom",
	"GD": "Grenada",
	"GE": "Georgia",
	"GF": "French Guiana",
	"GG": "Guernsey",
	"GH": "Ghana",
	"GI": "Gibraltar",
	"GL": "Greenland",
	"GM": "Gambia",
	"GN": "Guinea",
	"GP": "Guadeloupe",
	"GQ": "Equatorial Guinea",
	"GR": "Greece",
	"GS": "South Georgia and the South Sandwich Islands",
	"GT": "Guatemala",
	"GU": "Guam",
	"GW": "Guinea-Bissau",
	"GY": "Guyana",
	"HK": "Hong Kong",
	"HM": "Heard Island and McDonald Islands",
	"HN": "Honduras",
	"HR": "Croatia",
	"HT": "Haiti",
	"HU": "Hungary",
	"ID": "Indonesia",
	"IE": "Ireland",
	"IL": "Israel",
	"IM": "Isle of Man",
	"IN": "India",
	"IO": "British Indian Ocean Territory",
	"IQ": "Iraq",
	"IR": "Iran",
	"IS": "Iceland",
	"IT": "Italy",
	"JE": "Jersey",
	"JM": "Jamaica",
	"JO": "Jordan",
	"JP": "Japan",
	"KE": "Kenya",
	"KG": "Kyrgyzstan",
	"KH": "Cambodia",
	"KI": "Kiribati",
	"KM": "Comoros",
	"KN": "Saint Kitts and Nevis",
	"KP": "North Korea",
	"KR": "South Korea",
	"KW": "Kuwait",
	"KY": "Cayman Islands",
	"KZ": "Kazakhstan",
	"LA": "Laos",
	"LB": "Lebanon",
	"LC": "Saint Lucia",
	"LI": "Liechtenstein",
	"LK": "Sri Lanka",
	"LR": "Liberia",
	"LS": "Lesotho",
	"LT": "Lithuania",
	"LU": "Luxembourg",
	"LV": "Latvia",
	"LY": "Libya",
	"MA": "Morocco",
	"MC": "Monaco",
	"MD": "Moldova",
	"ME": "Montenegro",
	"MF": "Saint Martin (French)",
	"MG": "Madagascar",
	"MH": "Marshall Islands",
	"MK": "North Macedonia",
	"ML": "Mali",
	"MM": "Myanmar",
	"MN": "Mongolia",
	"MO": "Macao",
	"MP": "Northern Mariana Islands",
	"MQ": "Martinique",
	"MR": "Mauritania",
	"MS": "Montserrat",
	"MT": "Malta",
	"MU": "Mauritius",
	"MV": "Maldives",
	"MW": "Malawi",
	"MX": "Mexico",
	"MY": "Malaysia",
	"MZ": "Mozambique",
	"NA": "Namibia",
	"NC": "New Caledonia",
	"NE": "Niger",
	"NF": "Norfolk Island",
	"NG": "Nigeria",
	"NI": "Nicaragua",
	"NL": "Netherlands",
	"NO": "Norway",
	"NP": "Nepal",
	"NR": "Nauru",
	"NU": "Niue",
	"NZ": "New Zealand",
	"OM": "Oman",
	"PA": "Panama",
	"PE": "Peru",
	"PF": "French Polynesia",
	"PG": "Papua New Guinea",
	"PH": "Philippines",
	"PK": "Pakistan",
	"PL": "Poland",
	"PM": "Saint Pierre and Miquelon",
	"PN": "Pitcairn",
	"PR": "Puerto Rico",
	"PS": "Palestine",
	"PT": "Portugal",
	"PW": "Palau",
	"PY": "Paraguay",
	"QA": "Qatar",
	"RE": "Réunion",
	"RO": "Romania",
	"RS": "Serbia",
	"RU": "Russia",
	"RW": "Rwanda",
	"SA": "Saudi Arabia",
	"SB": "Solomon Islands",
	"SC": "Seychelles",
	"SD": "Sudan",
	"SE": "Sweden",
	"SG": "Singapore",
	"SH": "Saint Helena",
	"SI": "Slovenia",
	"SJ": "Svalbard and Jan Mayen",
	"SK": "Slovakia",
	"SL": "Sierra Leone",
	"SM": "San Marino",
	"SN": "Senegal",
	"SO": "Somalia",
	"SR": "Suriname",
	"SS": "South Sudan",
	"ST": "Sao Tome and Principe",
	"SV": "El Salvador",
	"SX": "Sint Maarten (Dutch)",
	"SY": "Syria",
	"SZ": "Eswatini",
	"TC": "Turks and Caicos Islands",
	"TD": "Chad",
	"TF": "French Southern Territories",
	"TG": "Togo",
	"TH": "Thailand",
	"TJ": "Tajikistan",
	"TK": "Tokelau",
	"TL": "Timor-Leste",
	"TM": "Turkmenistan",
	"TN": "Tunisia",
	"TO": "Tonga",
	"TR": "Turkey",
	"TT": "Trinidad and Tobago",
	"TV": "Tuvalu",
	"TW": "Taiwan",
	"TZ": "Tanzania",
	"UA": "Ukraine",
	"UG": "Uganda",
	"UM": "U.S. Minor Outlying Islands",
	"US": "United States",
	"UY": "Uruguay",
	"UZ": "Uzbekistan",
	"VA": "Vatican City",
	"VC": "Saint Vincent and the Grenadines",
	"VE": "Venezuela",
	"VG": "Virgin Islands (British)",
	"VI": "Virgin Islands (U.S.)",
	"VN": "Vietnam",
	"VU": "Vanuatu",
	"WF": "Wallis and Futuna",
	"WS": "Samoa",
	"YE": "Yemen",
	"YT": "Mayotte",
	"ZA": "South Africa",
	"ZM": "Zambia",
	"ZW": "Zimbabwe",
}

// A geo restriction's countries are joined into the regex of an if condition
// in the config of each host it applies to (^(KR|CN)$), matched against the
// country code the GeoIP lookup gives the client address: two upper-case
// letters, or "--" for an address it has no country for. Each priority allow
// entry is compared with the client address and listed in the host's
// ModSecurity file.
//
// A country is any two ASCII letters, not only a code from CommonCountryCodes
// (the list the country picker offers): the GeoIP database also gives codes
// such as XK, and a list saved before the API checked countries can hold
// them. It is saved, and written into the config, in upper case, the case the
// lookup gives; "kr" never matched before. "--" is kept too. Anything else is
// refused, and left out of the config with a warning: it is not a code the
// lookup gives, and as part of the regex it would change what the condition
// matches.

// NormalizeCountryCode returns c without the whitespace around it and in
// upper case, and whether that is a country code a geo restriction can hold:
// two ASCII letters, or "--".
func NormalizeCountryCode(c string) (string, bool) {
	c = strings.TrimSpace(c)
	if c == "--" {
		return c, true
	}
	if len(c) != 2 {
		return c, false
	}
	b := []byte(c)
	for i, ch := range b {
		switch {
		case ch >= 'A' && ch <= 'Z':
		case ch >= 'a' && ch <= 'z':
			b[i] = ch - ('a' - 'A')
		default:
			return c, false
		}
	}
	return string(b), true
}

// ValidateGeoLists checks the countries and priority allow entries of a per
// host geo restriction or of the global default, normalizing each entry (and
// saving it normalized): a country with NormalizeCountryCode, an entry
// with NormalizeIPOrCIDR. A nil slice is a field the request did not send.
//
// A country must be two letters (or "--"), and an entry an IP address or a
// CIDR range.
func ValidateGeoLists(countries, allowedIPs []string) error {
	for i := range countries {
		code, ok := NormalizeCountryCode(countries[i])
		if !ok {
			return fmt.Errorf("%w: countries[%d] %.20q is not a two-letter country code", ErrInvalidInput, i, countries[i])
		}
		countries[i] = code
	}
	for i := range allowedIPs {
		normalized, ok := NormalizeIPOrCIDR(strings.TrimSpace(allowedIPs[i]))
		if !ok {
			return fmt.Errorf("%w: allowed_ips[%d] %.60q is not an IP address or CIDR range", ErrInvalidInput, i, allowedIPs[i])
		}
		allowedIPs[i] = normalized
	}
	return nil
}

// ValidateChangedGeoLists is ValidateGeoLists for a save that sends the
// stored priority allow entries back, as the forms do (#320). An entry that
// is not an IP address or a CIDR range passes, unchanged, when stored
// holds it already: before v2.61.1 the field was not checked, so a stored
// list can hold a domain name, the configs leave it out, and it must not
// block a save of the rest of the form. A new one is refused, with
// CodeHostnameInIPField when it is a domain name (it goes in
// allowed_hostnames). Countries are all checked, and entries normalized, as
// ValidateGeoLists does; entries are compared without the whitespace around
// them.
func ValidateChangedGeoLists(countries, allowedIPs, stored []string) error {
	if err := ValidateGeoLists(countries, nil); err != nil {
		return err
	}
	kept := make(map[string]bool, len(stored))
	for _, s := range stored {
		kept[strings.TrimSpace(s)] = true
	}
	for i := range allowedIPs {
		entry := strings.TrimSpace(allowedIPs[i])
		if normalized, ok := NormalizeIPOrCIDR(entry); ok {
			allowedIPs[i] = normalized
			continue
		}
		if kept[entry] {
			continue
		}
		field := fmt.Sprintf("allowed_ips[%d]", i)
		if e := HostnameInIPField(field, entry, "allowed_hostnames"); e != nil {
			return e
		}
		return fmt.Errorf("%w: %s %.60q is not an IP address or CIDR range", ErrInvalidInput, field, allowedIPs[i])
	}
	return nil
}

// UsableGeoLists returns the countries and priority allow entries
// ValidateGeoLists accepts (normalized as it saves them), and the rest, for a
// restore that keeps what it can.
func UsableGeoLists(countries, allowedIPs []string) (validCountries, validIPs, dropped []string) {
	validCountries = countries[:0:0]
	for _, c := range countries {
		if code, ok := NormalizeCountryCode(c); ok {
			validCountries = append(validCountries, code)
		} else {
			dropped = append(dropped, c)
		}
	}
	validIPs = allowedIPs[:0:0]
	for _, ip := range allowedIPs {
		if normalized, ok := NormalizeIPOrCIDR(strings.TrimSpace(ip)); ok {
			validIPs = append(validIPs, normalized)
		} else {
			dropped = append(dropped, ip)
		}
	}
	return validCountries, validIPs, dropped
}
