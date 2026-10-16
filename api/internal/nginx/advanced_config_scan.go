package nginx

// Advanced Config is nginx text an operator writes for a host. NPG pastes it
// into the host's server block, or into its location / when it has no
// location of its own (advanced.conf.tmpl, waf.conf.tmpl). Two questions
// about it decide how an access list's domain entries (#320) are treated,
// and neither may depend on the block a directive sits in:
//   - AdvancedConfigHasAuth: the host asks for a login of its own, so a
//     "satisfy any" access list lets a listed address skip it
//     (ProxyHostConfigData.AccessPhaseAuth).
//   - AdvancedConfigHasAccessRules: some block of the host has access rules
//     of its own and does not follow the access list, so a 403 there is not
//     the list's (the fail2ban gate).
//
// Both answer conservatively: a directive in any block counts.
// advancedConfigHasTopLevel (manager.go) answers for the top level only, for
// other callers, and is left as it is.

// AdvancedConfigHasAuth reports whether text uses auth_request or auth_basic
// as a directive, in any block, outside comments and quoted strings.
// auth_request_set and auth_basic_user_file do not count.
func AdvancedConfigHasAuth(text string) bool {
	return advancedConfigDirectiveNames(text, func(name string) bool {
		return name == "auth_request" || name == "auth_basic"
	})
}

// AdvancedConfigHasAccessRules reports whether text uses allow, deny or
// satisfy as a directive, in any block, outside comments and quoted strings.
// satisfy counts: Advanced Config refuses it since v2.25.0, but a host saved
// before then, or restored from a backup, can still carry it.
func AdvancedConfigHasAccessRules(text string) bool {
	return advancedConfigDirectiveNames(text, func(name string) bool {
		return name == "allow" || name == "deny" || name == "satisfy"
	})
}

// advancedConfigDirectiveNames calls visit with the name of every directive
// in text, at any depth, and stops at the first call that returns true,
// reporting whether one did. Tokens follow nginx: "#" opens a comment and a
// quote a string only at the start of a word; a word ends at whitespace, ";"
// or "{" ("${" stays in the word); "\" escapes the next byte. The first word
// of the text, and the first after ";", "{" or "}", names a directive.
func advancedConfigDirectiveNames(text string, visit func(name string) bool) bool {
	atStart := true
	for i := 0; i < len(text); {
		switch c := text[i]; {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == '#':
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case c == ';' || c == '{' || c == '}':
			atStart = true
			i++
		case c == '"' || c == '\'':
			for i++; i < len(text) && text[i] != c; i++ {
				if text[i] == '\\' {
					i++
				}
			}
			i++
			atStart = false
		default:
			start := i
			for i < len(text) {
				b := text[i]
				if b == '\\' {
					i += 2
					continue
				}
				if b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == ';' || (b == '{' && !(i > start && text[i-1] == '$')) {
					break
				}
				i++
			}
			if atStart && visit(text[start:min(i, len(text))]) {
				return true
			}
			atStart = false
		}
	}
	return false
}
