package nginx

import (
	"path/filepath"

	"nginx-proxy-guard/internal/model"
)

// An access list's domain rows (#320) reach nginx as include lines, one per
// name, of the file the DNS entry service writes for the scope
// "acl:<list ID>" and that name (dns_includes.go). The rendered config holds
// only the file's path, so it depends on the database alone; the addresses
// are in the file.

// DNSIncludeLine is one include line of an access list block: the domain
// name, for the comment written above it, and the absolute path of its file.
type DNSIncludeLine struct {
	Name string
	Path string
}

// accessListDNSPath returns the path of the file of one of list's domain
// rows, or "" when the list's scope or the row's name is not one a file is
// written for (DNSIncludeRenderPath checks both again).
func accessListDNSPath(list *model.AccessList, item model.AccessListItem) string {
	return DNSIncludeRenderPath(model.AccessListDNSScope(list.ID), item.Hostname, ".allow")
}

// accessListDNSIncludes returns the include lines of list's domain rows, in
// the list's order, each file once. The template writes them after the
// list's address rules (accessListRules) and before its final "deny all", so
// an address rule, a deny included, wins over a domain. A row
// whose path cannot be built is not here: accessListRules writes it as
// "deny all" in its place.
func accessListDNSIncludes(list *model.AccessList) []DNSIncludeLine {
	if list == nil {
		return nil
	}
	var lines []DNSIncludeLine
	seen := make(map[string]bool)
	for _, item := range list.Items {
		if item.Hostname == "" {
			continue
		}
		path := accessListDNSPath(list, item)
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		lines = append(lines, DNSIncludeLine{Name: item.Hostname, Path: path})
	}
	return lines
}

// ensureDNSIncludes creates, empty, each domain include file the host config
// about to be written includes and that does not exist yet
// (EnsureDNSIncludeFile keeps an existing file's content): the access list
// block's .allow files and the exception lists' .geo files
// (hostDNSIncludeLines). nginx -t fails on a missing include, and SyncAll
// then removes the host that includes it. The lines come from the functions
// the template renders, so an SSL host, which renders the access list block
// twice, ensures each file once. No DNS lock is taken: GenerateConfigFull
// runs both inside and outside the nginx lock.
func (m *Manager) ensureDNSIncludes(data ProxyHostConfigData) error {
	return m.ensureDNSIncludeLines(hostDNSIncludeLines(data))
}

// ensureDNSIncludeLines creates, empty, the file of each of lines that does
// not exist yet (EnsureDNSIncludeFile), for a host config or nginx.conf.
func (m *Manager) ensureDNSIncludeLines(lines []DNSIncludeLine) error {
	for _, line := range lines {
		file := filepath.Base(line.Path)
		if err := m.EnsureDNSIncludeFile(file[:16], file[16:]); err != nil {
			return err
		}
	}
	return nil
}
