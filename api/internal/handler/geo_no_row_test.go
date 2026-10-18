package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/repository"
)

// A host without its own geo restriction, URI block or rate limit row gets the
// defaults. The domain names (#320) in them are an empty list, never null and
// never left out, so a client reads the field the same way with or without a
// row.
func TestNoRowAnswersCarryAnEmptyNameList(t *testing.T) {
	const hostID = "00000000-0000-0000-0000-000000000001"
	cases := []struct {
		name, field string
		call        func(t *testing.T) *httptest.ResponseRecorder
	}{
		{"geo restriction", "allowed_hostnames", func(t *testing.T) *httptest.ResponseRecorder {
			db, mock := newMockDB(t)
			dbw := &database.DB{DB: db}
			h := NewGeoHandler(repository.NewGeoRepository(dbw), repository.NewGlobalGeoRepository(dbw), repository.NewProxyHostRepository(dbw), nil, nil)
			row := proxyHostRow(hostID)
			mock.ExpectQuery(`SELECT id, COALESCE\(proxy_type`).WithArgs(hostID).
				WillReturnRows(sqlmock.NewRows(positionalColumnNames(len(row))).AddRow(row...))
			mock.ExpectQuery(`FROM geo_restrictions WHERE proxy_host_id`).WithArgs(hostID).
				WillReturnRows(sqlmock.NewRows([]string{"id"}))
			return callJSON(t, h.GetByProxyHost, http.MethodGet, "", "id", hostID)
		}},
		{"URI block", "exception_hostnames", func(t *testing.T) *httptest.ResponseRecorder {
			db, mock := newMockDB(t)
			h := newSecurityHandlerForTest(db)
			mock.ExpectQuery(`FROM uri_blocks WHERE proxy_host_id`).WithArgs(hostID).
				WillReturnRows(sqlmock.NewRows([]string{"id"}))
			return callJSON(t, h.GetURIBlock, http.MethodGet, "", "proxyHostId", hostID)
		}},
		{"rate limit", "whitelist_hostnames", func(t *testing.T) *httptest.ResponseRecorder {
			db, mock := newMockDB(t)
			h := newSecurityHandlerForTest(db)
			mock.ExpectQuery(`FROM rate_limits`).WithArgs(hostID).
				WillReturnRows(sqlmock.NewRows([]string{"id"}))
			return callJSON(t, h.GetRateLimit, http.MethodGet, "", "proxyHostId", hostID)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := tc.call(t)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d, want 200; body %s", rec.Code, rec.Body)
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("body %q: %v", rec.Body, err)
			}
			got, ok := body[tc.field]
			if !ok {
				t.Fatalf("the answer has no %q: %s", tc.field, rec.Body)
			}
			if string(got) != "[]" {
				t.Errorf("%q = %s, want []", tc.field, got)
			}
		})
	}
}
