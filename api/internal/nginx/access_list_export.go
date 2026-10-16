package nginx

import "nginx-proxy-guard/internal/model"

// AccessListRules returns the allow and deny rules an access list block
// renders, in order: what accessListRules gives the template. The DNS entry
// service's fail2ban evaluator walks the same rules as nginx (#320).
func AccessListRules(list *model.AccessList) []model.AccessListItem {
	return accessListRules(list)
}
