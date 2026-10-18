package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// The old zone names (rate_<id>) are read from every host's Advanced Config,
// disabled hosts included. A host with rate limiting whose read fails is not
// rendered: without it the config could lack an alias some Advanced Config
// uses, and nginx -t would fail on a zone it cannot attribute to a file.
func TestHostConfigDataReadsOldRateLimitZoneNames(t *testing.T) {
	const hostID = "00000000-0000-4000-8000-0000000003a1"
	const legacyRefs = `FROM proxy_hosts\s+WHERE advanced_config ~`
	host := &model.ProxyHost{ID: hostID, DomainNames: []string{"rl.example.com"}, Enabled: true}

	newService := func(t *testing.T) (*ProxyHostService, sqlmock.Sqlmock) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock: %v", err)
		}
		t.Cleanup(func() { db.Close() })
		mock.MatchExpectationsInOrder(false) // the lookups run in parallel
		now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
		mock.ExpectQuery(`FROM rate_limits`).WithArgs(hostID).
			WillReturnRows(sqlmock.NewRows(positionalColumns(13)).AddRow(
				"00000000-0000-4000-8000-0000000003a2", hostID, true, int64(10), int64(5),
				"10m", "ip", int64(429), "", false, now, now, "{}"))
		mock.ExpectQuery(`FROM banned_ips`).WillReturnRows(sqlmock.NewRows(positionalColumns(10)))
		mock.ExpectQuery(`FROM banned_ips`).WillReturnRows(sqlmock.NewRows(positionalColumns(10)))
		return &ProxyHostService{
			repo:          repository.NewProxyHostRepository(&database.DB{DB: db}),
			rateLimitRepo: repository.NewRateLimitRepository(db),
		}, mock
	}

	t.Run("read fails", func(t *testing.T) {
		s, mock := newService(t)
		readErr := errors.New("connection reset by peer")
		mock.ExpectQuery(legacyRefs).WillReturnError(readErr)

		if _, err := s.getHostConfigData(context.Background(), host); !errors.Is(err, readErr) {
			t.Fatalf("getHostConfigData error = %v, want the read's error", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
	})

	t.Run("a host uses the old name", func(t *testing.T) {
		s, mock := newService(t)
		mock.ExpectQuery(legacyRefs).WillReturnRows(sqlmock.NewRows([]string{"advanced_config"}).
			AddRow("location /slow {\n    limit_req zone=rate_00000000_0000_4000_8000_0000000003a1 burst=1;\n}"))

		data, err := s.getHostConfigData(context.Background(), host)
		if err != nil {
			t.Fatalf("getHostConfigData: %v", err)
		}
		if !data.LegacyRateZoneAlias {
			t.Error("rate_<id> is used by a host's Advanced Config but the alias is not set")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
	})
}
