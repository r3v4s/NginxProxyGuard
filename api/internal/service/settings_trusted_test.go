package service

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// nginx.conf's global trusted list (#320): the valid IP/CIDR lines, the
// domains and the WAF bypass flag. A settings read that fails trusts no one
// and bypasses no WAF, and nginx.conf keeps its structure.
func TestTrustedIPConfigForNginxConf(t *testing.T) {
	sys := &model.SystemSettings{
		GlobalTrustedIPs:          "192.0.2.10\nnot-an-ip\n# office\n192.0.2.64/26",
		GlobalTrustedHostnames:    []string{"office.example.com"},
		GlobalTrustedIPsBypassWAF: true,
	}
	got := ResolveTrustedIPConfig(sys)
	if !slices.Equal(got.Static, []string{"192.0.2.10", "192.0.2.64/26"}) ||
		!slices.Equal(got.Hostnames, []string{"office.example.com"}) || !got.BypassWAF {
		t.Errorf("ResolveTrustedIPConfig = %+v", got)
	}

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	mock.ExpectQuery(`FROM system_settings`).WillReturnError(errors.New("connection reset by peer"))
	s := &SettingsService{systemSettingsRepo: repository.NewSystemSettingsRepository(db)}
	if got := s.loadTrustedIPConfig(context.Background()); len(got.Static) != 0 || len(got.Hostnames) != 0 || got.BypassWAF {
		t.Errorf("after a failed read, loadTrustedIPConfig = %+v, want the zero value", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}
