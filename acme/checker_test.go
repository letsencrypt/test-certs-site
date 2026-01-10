package acme

import (
	"crypto/x509"
	"testing"
	"time"
)

func FuzzHalfTime(f *testing.F) {
	f.Add(int64(0))
	f.Add(int64(time.Minute))
	f.Add(int64(time.Hour))

	f.Fuzz(func(t *testing.T, delta int64) {
		now := time.Now()
		one := now.Add(time.Duration(delta))
		two := one.Add(time.Duration(delta))

		ht := halfTime(&x509.Certificate{
			NotBefore: now,
			NotAfter:  two,
		})

		if ht != one {
			t.Errorf("half time expected %v, got %v", one, ht)
		}
	})
}
