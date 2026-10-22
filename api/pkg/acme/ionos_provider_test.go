package acme

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"

	"nginx-proxy-guard/internal/model"
)

const (
	ionosTestPrefix = "pubprefix0123"
	ionosTestSecret = "ionos-secret-0123456789"
)

// ionosAPI stands in for the IONOS DNS API: it records the X-Api-Key of every
// request and refuses it, as IONOS does a key it does not know.
type ionosAPI struct{ keys []string }

func (a *ionosAPI) RoundTrip(r *http.Request) (*http.Response, error) {
	a.keys = append(a.keys, r.Header.Get("X-Api-Key"))
	return &http.Response{
		StatusCode: http.StatusUnauthorized,
		Status:     http.StatusText(http.StatusUnauthorized),
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`[{"code":"UNAUTHORIZED","message":"The customer is not authorized to do this operation."}]`)),
		Request:    r,
	}, nil
}

// fakeIonosAPI makes every HTTP request of the test reach an ionosAPI instead
// of the network, and turns off lego's CNAME lookup so no DNS query is sent.
func fakeIonosAPI(t *testing.T) *ionosAPI {
	t.Helper()
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	api := &ionosAPI{}
	old := http.DefaultTransport
	http.DefaultTransport = api
	t.Cleanup(func() { http.DefaultTransport = old })
	return api
}

// IONOS takes the key as one X-Api-Key value, prefix.secret, joined from the
// two halves NPG stores. Halves are trimmed and a secret pasted together with
// its prefix loses the copy, because a row restored from a backup was never
// checked by the API. lego waits up to 10 minutes for the record, as for
// Dynu: IONOS nameservers are slow, and a renewal holds its lock for 10.
func TestIonosProviderSendsPrefixDotSecret(t *testing.T) {
	api := fakeIonosAPI(t)
	const want = ionosTestPrefix + "." + ionosTestSecret

	for name, creds := range map[string]model.IonosCredentials{
		"as entered":            {APIKeyPrefix: ionosTestPrefix, APIKey: ionosTestSecret},
		"padded halves":         {APIKeyPrefix: " " + ionosTestPrefix + "\n", APIKey: "\t" + ionosTestSecret + " "},
		"whole key as secret":   {APIKeyPrefix: ionosTestPrefix, APIKey: want},
		"padded whole key also": {APIKeyPrefix: ionosTestPrefix + " ", APIKey: " " + want + "\n"},
	} {
		t.Run(name, func(t *testing.T) {
			p, err := (&Service{}).newDNS01Provider(dnsProviderOf(t, model.DNSProviderIonos, creds))
			if err != nil {
				t.Fatal(err)
			}
			timeouts, ok := p.(challenge.ProviderTimeout)
			if !ok {
				t.Fatal("the IONOS provider has no Timeout")
			}
			if timeout, interval := timeouts.Timeout(); timeout != 10*time.Minute || interval != 10*time.Second {
				t.Errorf("Timeout() = %s, %s; want 10m0s, 10s", timeout, interval)
			}

			sent := len(api.keys)
			err = p.Present("www.example.com", "token", "keyAuth")
			if err == nil {
				t.Fatal("Present succeeded against an API that refuses every key")
			}
			if len(api.keys) != sent+1 {
				t.Fatalf("Present sent %d requests, want 1", len(api.keys)-sent)
			}
			if got := api.keys[sent]; got != want {
				t.Errorf("X-Api-Key = %q, want %q", got, want)
			}
			if strings.Contains(err.Error(), ionosTestSecret) {
				t.Errorf("the secret is in the error: %v", err)
			}
		})
	}
}

// Joined, missing halves would still make a non-empty key ("." or
// "prefix."), so lego's own "credentials missing" check would never fire and
// the row would fail only at IONOS, as a 401.
func TestIonosProviderRefusesAMissingHalf(t *testing.T) {
	for name, creds := range map[string]model.IonosCredentials{
		"neither":        {},
		"no secret":      {APIKeyPrefix: ionosTestPrefix},
		"no prefix":      {APIKey: ionosTestSecret},
		"blank halves":   {APIKeyPrefix: " ", APIKey: "\t\n"},
		"blank secret":   {APIKeyPrefix: ionosTestPrefix, APIKey: "  "},
		"prefix and dot": {APIKeyPrefix: ionosTestPrefix, APIKey: ionosTestPrefix + "."},
		"blank prefix":   {APIKeyPrefix: "   ", APIKey: ionosTestSecret},
	} {
		_, err := (&Service{}).newDNS01Provider(dnsProviderOf(t, model.DNSProviderIonos, creds))
		if err == nil {
			t.Errorf("%s: a provider was built from %+v", name, creds)
		} else if strings.Contains(err.Error(), ionosTestSecret) {
			t.Errorf("%s: the secret is in the error: %v", name, err)
		}
	}
}
