package service

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"nginx-proxy-guard/internal/repository"
)

// restoreAuditDetails is a sqlmock argument matcher that decodes the
// details JSON an audit entry hands to the driver.
type restoreAuditDetails struct{ into *map[string]interface{} }

func (a restoreAuditDetails) Match(v driver.Value) bool {
	b, ok := v.([]byte)
	return ok && json.Unmarshal(b, a.into) == nil
}

// The restore audit keeps its own keys and adds what the restore passes: the
// domain names it brought back and those waiting for review (#320).
func TestLogBackupRestoreAddsTheExtraDetails(t *testing.T) {
	for _, tc := range []struct {
		extra map[string]interface{}
		want  map[string]interface{}
	}{
		{nil, map[string]interface{}{"action": "restore", "name": "backup.tar.gz"}},
		{
			map[string]interface{}{"dns_names": []string{"partner.example.com"}, "dns_names_total": 1,
				"dns_needs_review": []string{}, "action": "replaced", "name": "replaced"},
			map[string]interface{}{"action": "restore", "name": "backup.tar.gz",
				"dns_names": []interface{}{"partner.example.com"}, "dns_names_total": float64(1), "dns_needs_review": []interface{}{}},
		},
	} {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		var details map[string]interface{}
		mock.ExpectExec(`INSERT INTO audit_logs`).
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "backup_restored", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
				restoreAuditDetails{&details}, sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(0, 1))
		svc := NewAuditService(repository.NewAuditLogRepository(db))
		if err := svc.LogBackupRestore(context.Background(), "backup.tar.gz", tc.extra); err != nil {
			t.Fatalf("LogBackupRestore: %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(details, tc.want) {
			t.Errorf("details = %v, want %v", details, tc.want)
		}
		db.Close()
	}
}
