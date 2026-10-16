package handler

import (
	"context"
	"reflect"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// fakeAccessListReader serves one list and counts the reads.
type fakeAccessListReader struct {
	list  *model.AccessList
	reads int
}

func (f *fakeAccessListReader) GetByID(_ context.Context, id string) (*model.AccessList, error) {
	f.reads++
	if f.list == nil || f.list.ID != id {
		return nil, nil
	}
	return f.list, nil
}

// Linking a host to a list with domains lets whoever controls those domains'
// DNS reach the host, so the update audit names them. An
// update that leaves the link alone reads nothing: the update path's queries
// are pinned (proxy_host_reload_rejected_test.go).
func TestHostUpdateAuditNamesTheDomainsOfANewlyLinkedList(t *testing.T) {
	ctx := context.Background()
	listID, gone := testListID, "00000000-0000-4000-8000-0000000016d1"
	host := func(id *string) *model.ProxyHost { return &model.ProxyHost{AccessListID: id} }
	reader := &fakeAccessListReader{list: &model.AccessList{ID: listID, Items: []model.AccessListItem{
		addressRule("allow", "192.0.2.10", 0), domainRule("partner.example.com", 1), domainRule("shop.example.com", 2),
	}}}

	got := linkedAccessListDNSNames(ctx, reader, host(nil), host(&listID))
	if want := []string{"partner.example.com", "shop.example.com"}; !reflect.DeepEqual(got, want) {
		t.Errorf("newly linked: %v, want %v", got, want)
	}
	reads := reader.reads
	if got := linkedAccessListDNSNames(ctx, reader, host(&listID), host(&listID)); got != nil {
		t.Errorf("unchanged link: %v, want none", got)
	}
	if got := linkedAccessListDNSNames(ctx, reader, host(&listID), host(nil)); got != nil {
		t.Errorf("unlinked: %v, want none", got)
	}
	if reader.reads != reads {
		t.Errorf("%d reads for updates that linked no list", reader.reads-reads)
	}
	if got := linkedAccessListDNSNames(ctx, reader, host(nil), host(&gone)); got != nil {
		t.Errorf("a list that is gone: %v, want none", got)
	}
	if got := linkedAccessListDNSNames(ctx, nil, host(nil), host(&listID)); got != nil {
		t.Errorf("without a reader: %v, want none", got)
	}
}
