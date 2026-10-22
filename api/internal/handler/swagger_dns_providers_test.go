package handler

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// Generated clients check provider_type against these enums and read the
// credential shape from the description, so every type the API accepts must
// be in both enums and described (#232; IONOS was missing from both). The
// types are the ones the API's own check lists when it refuses an unknown one.
func TestSwaggerListsEveryDNSProviderType(t *testing.T) {
	refused := (&repository.DNSProviderRepository{}).TestConnection(context.Background(), "no-such-type", nil)
	_, list, ok := strings.Cut(fmt.Sprint(refused), "supported: ")
	if !ok {
		t.Fatalf("the unsupported-type error no longer lists the supported types: %v", refused)
	}
	types := strings.Split(list, ", ")
	sort.Strings(types)

	enum := regexp.MustCompile(`\n\s+enum: \[([^\]]*)\]`)
	for _, schema := range []string{"DNSProvider", "CreateDNSProvider"} {
		m := enum.FindStringSubmatch(swaggerSchemaBlock(t, schema))
		if m == nil {
			t.Errorf("%s has no provider_type enum", schema)
			continue
		}
		got := strings.Split(m[1], ", ")
		sort.Strings(got)
		if !reflect.DeepEqual(got, types) {
			t.Errorf("%s provider_type enum = %v, want %v", schema, got, types)
		}
	}

	create := swaggerSchemaBlock(t, "CreateDNSProvider")
	for _, providerType := range types {
		if !strings.Contains(create, providerType+":") {
			t.Errorf("CreateDNSProvider does not describe the %s credentials", providerType)
		}
	}
	for _, field := range modelJSONNames(reflect.TypeOf(model.IonosCredentials{})) {
		if !strings.Contains(create, field) {
			t.Errorf("CreateDNSProvider does not name the IONOS field %s", field)
		}
	}
}
