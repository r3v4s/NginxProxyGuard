package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// ionosProvRepo checks credentials with the real repository check, which
// touches no database for IONOS, and keeps what Create and Update would store.
type ionosProvRepo struct {
	fakeProvRepo
	stored json.RawMessage
}

func (r *ionosProvRepo) TestConnection(ctx context.Context, providerType string, creds json.RawMessage) error {
	return (&repository.DNSProviderRepository{}).TestConnection(ctx, providerType, creds)
}

func (r *ionosProvRepo) Create(_ context.Context, req *model.CreateDNSProviderRequest) (*model.DNSProvider, error) {
	r.stored = req.Credentials
	return &model.DNSProvider{ProviderType: req.ProviderType, Credentials: req.Credentials}, nil
}

func (r *ionosProvRepo) Update(_ context.Context, _ string, req *model.UpdateDNSProviderRequest) (*model.DNSProvider, error) {
	if req.Credentials != nil {
		r.stored = *req.Credentials
	}
	return r.prov, nil
}

// An IONOS key is a pair, so a half that is missing or blank is refused on
// create and on update (ErrInvalidCredentials, a 400). What is stored is what
// IONOS is sent: both halves trimmed, and the secret without a copy of the
// prefix when the whole key was pasted into the secret field.
func TestIonosCredentialsAreCheckedAndStoredTrimmed(t *testing.T) {
	const prefix, secret = "pubprefix0123", "ionos-secret-0123456789"
	want := model.IonosCredentials{APIKeyPrefix: prefix, APIKey: secret}
	existing := &model.DNSProvider{ID: "p1", ProviderType: model.DNSProviderIonos,
		Credentials: json.RawMessage(`{"api_key_prefix":"pubprefix0123","api_key":"ionos-secret-0123456789"}`)}

	for _, tc := range []struct {
		creds    string
		accepted bool
	}{
		{`{"api_key_prefix":"pubprefix0123","api_key":"ionos-secret-0123456789"}`, true},
		{`{"api_key_prefix":" pubprefix0123\n","api_key":"\tionos-secret-0123456789 "}`, true},
		{`{"api_key_prefix":"pubprefix0123","api_key":"pubprefix0123.ionos-secret-0123456789"}`, true},
		{`{"api_key":"ionos-secret-0123456789"}`, false},
		{`{"api_key_prefix":"pubprefix0123"}`, false},
		{`{}`, false},
		{`{"api_key_prefix":" ","api_key":" "}`, false},
		{`{"api_key_prefix":"pubprefix0123","api_key":"\t"}`, false},
		{`{"api_key_prefix":"  ","api_key":"ionos-secret-0123456789"}`, false},
		{`{"api_key_prefix":"pubprefix0123","api_key":"pubprefix0123."}`, false},
	} {
		raw := json.RawMessage(tc.creds)

		create := &ionosProvRepo{}
		_, createErr := (&DNSProviderService{repo: create}).Create(context.Background(),
			&model.CreateDNSProviderRequest{Name: "n", ProviderType: model.DNSProviderIonos, Credentials: raw})

		update := &ionosProvRepo{fakeProvRepo: fakeProvRepo{prov: existing}}
		_, updateErr := (&DNSProviderService{repo: update}).Update(context.Background(), "p1",
			&model.UpdateDNSProviderRequest{Credentials: &raw})

		for op, got := range map[string]struct {
			err    error
			stored json.RawMessage
		}{"create": {createErr, create.stored}, "update": {updateErr, update.stored}} {
			if !tc.accepted {
				if !errors.Is(got.err, model.ErrInvalidCredentials) {
					t.Errorf("%s %s: err = %v, want ErrInvalidCredentials", op, tc.creds, got.err)
				} else if strings.Contains(got.err.Error(), secret) {
					t.Errorf("%s %s: the secret is in the error: %v", op, tc.creds, got.err)
				}
				if got.stored != nil {
					t.Errorf("%s %s: stored %s", op, tc.creds, got.stored)
				}
				continue
			}
			if got.err != nil {
				t.Errorf("%s %s: %v", op, tc.creds, got.err)
				continue
			}
			var stored model.IonosCredentials
			if err := json.Unmarshal(got.stored, &stored); err != nil || stored != want {
				t.Errorf("%s %s: stored %s, want %+v", op, tc.creds, got.stored, want)
			}
		}
	}
}
