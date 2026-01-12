package acme

import (
	"crypto/x509"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/certificate"
)

type mockARI struct {
	response *certificate.RenewalInfoResponse
	err      error
}

func (a mockARI) GetRenewalInfo(_ certificate.RenewalInfoRequest) (*certificate.RenewalInfoResponse, error) {
	return a.response, a.err
}

func TestCheckValid(t *testing.T) {
	t.Parallel()

	v := &valid{
		ari: mockARI{response: nil, err: api.ErrNoARI},
	}

	if v.shouldRevoke() {
		t.Fatal("valid certs should not revoke")
	}

	now := time.Now()

	currentCert := x509.Certificate{
		SerialNumber: big.NewInt(123),
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Minute),
	}

	at := v.checkRenew(t.Context(), &currentCert)
	if at.After(currentCert.NotAfter) {
		t.Fatal("renew time is after expiry date")
	}

	readyTime, err := v.checkReady(t.Context(), &currentCert, nil)
	if err != nil {
		t.Fatal("currentCert should be ready")
	}

	if readyTime.After(time.Now()) {
		t.Fatal("currentCert should be ready now")
	}

	old := x509.Certificate{
		NotAfter: now.Add(-time.Minute),
	}

	_, err = v.checkReady(t.Context(), &old, nil)
	if err == nil {
		t.Fatal("expired cert should return error from valid.checkReady")
	}
}

func TestValidARI(t *testing.T) {
	t.Parallel()

	now := time.Now()

	minuteAhead := now.Add(time.Minute)
	hourAhead := now.Add(time.Hour)

	v := &valid{
		logger: slog.Default(),
		ari: mockARI{response: &certificate.RenewalInfoResponse{
			RenewalInfoResponse: acme.RenewalInfoResponse{
				SuggestedWindow: acme.Window{
					Start: minuteAhead,
					End:   hourAhead,
				},
			},
			RetryAfter: time.Hour,
		}},
	}

	renewTime := v.checkRenew(t.Context(), &x509.Certificate{})

	if renewTime.Before(minuteAhead) {
		t.Fatalf("readyTime should not be before window: %v %v", renewTime, minuteAhead)
	}

	if renewTime.After(hourAhead) {
		t.Fatalf("readyTime should not be after window: %v %v", renewTime, hourAhead)
	}
}
