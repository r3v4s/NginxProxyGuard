package handler

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

// The global settings save, reset and preset, and the global URI block save,
// apply their change to every host and reload nginx. When the running nginx
// refuses that reload, the change is saved and recorded in the audit log, and
// the save answers 409 nginx_reload_rejected like every other save.

// fakeNginxDocker is the docker CLI the nginx manager runs, for an nginx
// container in which nginx -t passes and a reload is signalled. With
// NPG_FAKE_NGINX=refuse nginx keeps its worker and its log has the [emerg]
// line of a port in use. With accept, each reload starts a new worker. With
// broken, the reload signal fails.
const fakeNginxDocker = `#!/bin/sh
state="$NPG_FAKE_NGINX_STATE/reloads"
case "$1" in
logs)
	if [ "$NPG_FAKE_NGINX" = refuse ]; then
		echo "2026/10/12 09:00:00 [emerg] 1#1: bind() to 0.0.0.0:18998 failed (98: Address in use)" >&2
	fi
	exit 0 ;;
exec)
	case "$3" in
	nginx)
		if [ "$4" = -s ]; then
			if [ "$NPG_FAKE_NGINX" = broken ]; then
				echo "Error response from daemon: container is restarting" >&2
				exit 1
			fi
			if [ "$NPG_FAKE_NGINX" = accept ]; then
				echo reload >> "$state"
			fi
		fi
		exit 0 ;;
	sh)
		reloads=0
		if [ -e "$state" ]; then
			reloads=$(wc -l < "$state")
		fi
		printf '1\n1 (nginx) S 0 1 1 0\n%d (nginx) S 1 1 1 0\n' $((10 + reloads))
		exit 0 ;;
	esac ;;
esac
echo "unexpected: docker $*" >&2
exit 1
`

// newFakeDockerNginx returns an nginx manager over temp dirs whose docker is
// fakeNginxDocker in mode, with reload confirmation on.
func newFakeDockerNginx(t *testing.T, mode string) *nginx.Manager {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(fakeNginxDocker), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("NPG_FAKE_NGINX", mode)
	t.Setenv("NPG_FAKE_NGINX_STATE", dir)
	t.Setenv("NGINX_SKIP_TEST", "")
	m := nginx.NewManager(filepath.Join(dir, "nginx", "conf.d"), filepath.Join(dir, "certs"))
	m.SetHealthProber(nginx.NewHealthProber("npg-proxy", "80", false))
	return m
}

// acceptingNginx is an nginx manager for SyncAllConfigs whose test and
// reload pass. The NginxManager methods it does not define are nil and panic
// if called.
type acceptingNginx struct{ service.NginxManager }

func (acceptingNginx) RemoveOrphanedHostConfigs(context.Context, func(context.Context) ([]model.ProxyHost, error)) []string {
	return nil
}

func (acceptingNginx) TestConfig(context.Context) error { return nil }

func (acceptingNginx) ReloadNginx(context.Context) error { return nil }

// newGlobalSettingsHandler returns a settings handler over a mocked database:
// its hosts are applied through hosts (SyncAllConfigs), and nginx.conf and
// the last reload through a manager whose docker answers in nginxMode.
func newGlobalSettingsHandler(t *testing.T, hosts service.NginxManager, nginxMode string) (*SettingsHandler, sqlmock.Sqlmock) {
	t.Helper()
	db, mock := newMockDB(t)
	dbw := &database.DB{DB: db}
	phs := service.NewProxyHostService(repository.NewProxyHostRepository(dbw),
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, hosts)
	svc := service.NewSettingsService(repository.NewGlobalSettingsRepository(db), nil, nil, nil, nil, nil, nil, nil,
		newFakeDockerNginx(t, nginxMode), phs, nil, nil, "")
	return NewSettingsHandler(svc, service.NewAuditService(repository.NewAuditLogRepository(db)), nil), mock
}

// expectSettingsUpdate expects the global settings row to be written and read
// back (no row: the defaults), then SyncAllConfigs' list of hosts (none).
func expectSettingsUpdate(mock sqlmock.Sqlmock) {
	mock.ExpectExec(`INSERT INTO global_settings`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE global_settings SET`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`FROM global_settings`).WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectQuery(`FROM proxy_hosts\s+WHERE enabled = true`).WillReturnRows(sqlmock.NewRows([]string{"id"}))
}

func TestGlobalSettingsSaveRefusedByNginxIsAuditedAndAnswered409(t *testing.T) {
	h, mock := newGlobalSettingsHandler(t, refusingNginx{}, "refuse")
	expectSettingsUpdate(mock)
	expectAudit(mock, "settings_updated")

	expectRefusal(t, callJSON(t, h.UpdateGlobalSettings, http.MethodPut, `{}`))
}

func TestGlobalSettingsResetRefusedByNginxIsAuditedAndAnswered409(t *testing.T) {
	h, mock := newGlobalSettingsHandler(t, refusingNginx{}, "refuse")
	mock.ExpectExec(`DELETE FROM global_settings`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO global_settings`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`FROM global_settings`).WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectQuery(`FROM proxy_hosts\s+WHERE enabled = true`).WillReturnRows(sqlmock.NewRows([]string{"id"}))
	expectAudit(mock, "settings_updated")

	expectRefusal(t, callJSON(t, h.ResetGlobalSettings, http.MethodPost, ``))
}

func TestGlobalSettingsPresetRefusedByNginxIsAuditedAndAnswered409(t *testing.T) {
	h, mock := newGlobalSettingsHandler(t, refusingNginx{}, "refuse")
	expectSettingsUpdate(mock)
	expectAudit(mock, "settings_updated")

	expectRefusal(t, callJSON(t, h.ApplySettingsPreset, http.MethodPost, ``, "preset", "balanced"))
}

// The save reloads nginx twice: once for the hosts (SyncAllConfigs), and once
// more at the end, which also loads the redirect hosts. When nginx takes that
// last reload, it runs everything the save wrote.
func TestGlobalSettingsSaveAnswers200WhenNginxTakesTheLastReload(t *testing.T) {
	h, mock := newGlobalSettingsHandler(t, refusingNginx{}, "accept")
	expectSettingsUpdate(mock)
	expectAudit(mock, "settings_updated")

	if rec := callJSON(t, h.UpdateGlobalSettings, http.MethodPut, `{}`); rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body %s", rec.Code, rec.Body)
	}
}

// A reload that fails for any other reason is logged, and the save answers
// 200 as before.
func TestGlobalSettingsSaveAnswers200WhenTheReloadFailsOtherwise(t *testing.T) {
	h, mock := newGlobalSettingsHandler(t, acceptingNginx{}, "broken")
	expectSettingsUpdate(mock)
	expectAudit(mock, "settings_updated")

	if rec := callJSON(t, h.UpdateGlobalSettings, http.MethodPut, `{}`); rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body %s", rec.Code, rec.Body)
	}
}

func TestGlobalURIBlockSaveRefusedByNginxIsAuditedAndAnswered409(t *testing.T) {
	db, mock := newMockDB(t)
	dbw := &database.DB{DB: db}
	svc := service.NewSecurityService(nil, nil, nil, nil, nil, newRefusingHostService(dbw), nil,
		repository.NewURIBlockRepository(dbw), nil, nil)
	h := NewSecurityHandler(svc, service.NewAuditService(repository.NewAuditLogRepository(db)))
	saved := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	mock.ExpectQuery(`FROM global_uri_blocks`).WillReturnRows(sqlmock.NewRows([]string{"id"})) // the handler's read: none yet
	mock.ExpectQuery(`FROM global_uri_blocks`).WillReturnRows(sqlmock.NewRows([]string{"id"})) // the upsert's
	mock.ExpectExec(`INSERT INTO global_uri_blocks`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`FROM global_uri_blocks`).WillReturnRows(sqlmock.NewRows(
		[]string{"id", "enabled", "rules", "exception_ips", "allow_private_ips", "created_at", "updated_at", "exception_hostnames"}).
		AddRow("00000000-0000-4000-8000-0000000004a1", true, []byte(`[]`), "{}", true, saved, saved, "{}"))
	mock.ExpectQuery(`FROM proxy_hosts\s+WHERE enabled = true`).WillReturnRows(sqlmock.NewRows([]string{"id"}))
	expectAudit(mock, "global_uri_block_enabled")

	expectRefusal(t, callJSON(t, h.UpdateGlobalURIBlock, http.MethodPut, `{"enabled":true,"rules":[]}`))
}
