// Package acme handles issuing certificates via ACME
package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"log/slog"
	mathrand "math/rand/v2"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"

	"github.com/letsencrypt/test-certs-site/certs"
	"github.com/letsencrypt/test-certs-site/config"
	"github.com/letsencrypt/test-certs-site/scheduler"
	"github.com/letsencrypt/test-certs-site/storage"
)

func slogErr(err error) slog.Attr {
	return slog.String("error", err.Error())
}

// legoUser implements lego's registration.User interface.
type legoUser struct {
	reg *registration.Resource
	key *ecdsa.PrivateKey
}

func (u *legoUser) GetEmail() string {
	return ""
}

func (u *legoUser) GetRegistration() *registration.Resource {
	return u.reg
}

func (u *legoUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// New sets up the ACME client, registering it with the ACME server if one isn't present.
func New(cfg *config.Config, store *storage.Storage, schedule *scheduler.Schedule, manager *certs.CertManager) error {
	var user legoUser

	// Lego users can configure a custom logger by setting it in this global.
	log.Logger = slog.NewLogLogger(slog.Default().Handler(), slog.LevelInfo)

	// Try to load an existing ACME account
	accountURI, acctKey, err := store.ReadACME(cfg.ACME.Directory)
	if err != nil {
		// No account, need to make a new one
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		user.key = key
	} else {
		user = legoUser{
			reg: &registration.Resource{
				URI: accountURI,
			},
			key: acctKey,
		}
		slog.Info("Loaded ACME account", slog.String("directory", cfg.ACME.Directory), slog.String("User", user.reg.URI))
	}

	legoCfg := lego.NewConfig(&user)
	legoCfg.CADirURL = cfg.ACME.Directory
	legoCfg.UserAgent = "test-certs-site/1.0"

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return err
	}

	// Register if needed
	if user.reg == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: cfg.ACME.TermsOfServiceAgreed,
		})
		if err != nil {
			return err
		}
		user.reg = reg

		err = store.StoreACME(cfg.ACME.Directory, reg.URI, user.key)
		if err != nil {
			return err
		}
		slog.Info("Created new ACME account", slog.String("directory", cfg.ACME.Directory), slog.String("User", user.reg.URI))
	}

	err = client.Challenge.SetTLSALPN01Provider(manager)
	if err != nil {
		return err
	}

	for _, site := range cfg.Sites {
		for domain, chkr := range map[string]checker{
			site.Domains.Valid:   valid{},
			site.Domains.Revoked: revoked{},
			site.Domains.Expired: expired{},
		} {
			i := issuer{
				checker: chkr,

				domain:   domain,
				issuerCN: site.IssuerCN,
				keyType:  site.KeyType,
				profile:  site.Profile,

				client:   client,
				logger:   slog.With(slog.String("domain", domain)),
				manager:  manager,
				schedule: schedule,
				store:    store,
			}

			// Start each issuer within the next minute, but not all at once
			schedule.RunIn(time.Duration(mathrand.Int64N(int64(time.Minute))), i.start)
		}
	}

	return nil
}

type issuer struct {
	checker

	domain   string
	issuerCN string
	keyType  string
	profile  string

	client   *lego.Client
	logger   *slog.Logger
	manager  *certs.CertManager
	schedule *scheduler.Schedule
	store    *storage.Storage
}

// checker is the interface used to handle the differences between (valid, revoked, expired) by the issue state machine.
type checker interface {
	// checkReady returns if a certificate is ready.
	// It returns a time to wait with a nil error if we should wait and re-check.
	// If that time has already passed, then the cert is ready to go.
	// It returns an error if we should throw out this cert.
	checkReady(cert *x509.Certificate) (time.Time, error)

	// checkRenew returns when we should renew it.
	checkRenew(cert *x509.Certificate) time.Time

	shouldRevoke() bool
}

type valid struct{}

func (valid) checkReady(cert *x509.Certificate) (time.Time, error) {
	if time.Now().After(cert.NotAfter) {
		return time.Time{}, fmt.Errorf("certificate expired: %s", cert.NotAfter.Format(time.DateTime))
	}

	return time.Time{}, nil
}

func (valid) checkRenew(cert *x509.Certificate) time.Time {
	// TODO: Use ARI, recheck daily
	// Renew at 50% lifetime
	lifetime := cert.NotAfter.Sub(cert.NotBefore)

	return cert.NotBefore.Add(lifetime / 2) //nolint:mnd
}

func (valid) shouldRevoke() bool {
	return false
}

type revoked struct{}

func (revoked) checkReady(cert *x509.Certificate) (time.Time, error) {
	if time.Now().After(cert.NotAfter) {
		return time.Time{}, fmt.Errorf("certificate expired: %s", cert.NotAfter.Format(time.DateTime))
	}

	// TODO: Actually check CRLs.
	return cert.NotBefore.Add(time.Hour), nil
}

func (revoked) checkRenew(cert *x509.Certificate) time.Time {
	// Can't use ARI for revoked, because it'll want to revoke immediately
	// Renew at 50% lifetime
	lifetime := cert.NotAfter.Sub(cert.NotBefore)

	return cert.NotBefore.Add(lifetime / 2) //nolint:mnd
}

func (revoked) shouldRevoke() bool {
	return true
}

type expired struct{}

func (expired) checkReady(cert *x509.Certificate) (time.Time, error) {
	// Certificate is "ready" when it is expired
	return cert.NotAfter, nil
}

func (expired) checkRenew(cert *x509.Certificate) time.Time {
	// Expired certs could just hang out forever, but we should still routinely replace them
	// That makes sure any certificate changes will still show up.
	// We kick off the renewal once it's been expired for its lifetime
	lifetime := cert.NotAfter.Sub(cert.NotBefore)

	return cert.NotAfter.Add(lifetime)
}

func (expired) shouldRevoke() bool {
	return false
}

func (i *issuer) start() {
	// Check if the current certificate is good
	curr, err := i.store.ReadCurrent(i.domain)
	if err != nil {
		i.logger.Error("reading current certificate", slogErr(err))
		i.issue()

		return
	}

	renew := i.checkRenew(curr.Leaf)
	if time.Now().After(renew) {
		// Renewal time has come
		i.issue()

		return
	}

	// Otherwise, schedule rechecking into the future
	i.logger.Info("scheduling renewal", slog.String("at", renew.Format(time.DateTime)))
	i.schedule.RunAt(renew, func() { i.start() })
}

func (i *issuer) issue() {
	// Check if there's a next certificate already in progress
	next, err := i.store.ReadNext(i.domain)
	if err != nil {
		i.logger.Info("no next certificate, starting issuance", slogErr(err))
		i.issueNext()

		return
	}

	readyTime, err := i.checkReady(next.Leaf)
	if err != nil {
		i.logger.Info("next cert problem, starting issuance", slogErr(err))
		i.issueNext()

		return
	}

	if time.Now().After(readyTime) {
		// Next cert is ready! Take it.
		_, err := i.store.TakeNext(i.domain)
		if err != nil {
			i.logger.Info("TakeNext failed, starting over", slogErr(err))
			i.issueNext()

			return
		}
		err = i.manager.LoadCertificate(i.domain)
		if err != nil {
			i.logger.Info("loading certificate failed, starting over", slogErr(err))
			i.issueNext()

			return
		}

		i.logger.Info("certificate issuance completed")

		return
	}

	// Re-check at readyTime
	i.schedule.RunAt(readyTime, func() { i.issue() })
}

// issueNext is called to actually complete ACME validation.
func (i *issuer) issueNext() {
	key, err := i.store.StoreNextKey(i.domain, i.keyType)
	if err != nil {
		// This probably means something's pretty busted, just keep retrying from the top
		i.logger.Error("could not store next key", slogErr(err))
		i.schedule.RunIn(time.Minute, func() { i.start() })

		return
	}
	resp, err := i.client.Certificate.Obtain(certificate.ObtainRequest{
		Profile:        i.profile,
		Domains:        []string{i.domain},
		Bundle:         true,
		PrivateKey:     key,
		PreferredChain: i.issuerCN,
	})
	if err != nil {
		i.logger.Error("could not obtain certificate", slogErr(err))

		// Retry after a delay
		i.schedule.RunIn(time.Minute, func() { i.issueNext() })

		return
	}

	if i.shouldRevoke() {
		// Revoke with reason keyCompromise because browsers believe that one
		reasonKeyCompromise := uint(0)
		err := i.client.Certificate.RevokeWithReason(resp.Certificate, &reasonKeyCompromise)
		if err != nil {
			// TODO: if we failed to revoke, we should probably retry
			// Give up and run from the top
			i.schedule.RunIn(time.Minute, func() { i.start() })

			return
		}
	}

	err = i.store.StoreNextCert(i.domain, resp.Certificate)
	if err != nil {
		i.logger.Error("could not store next certificate", slogErr(err))
		// This probably means something's pretty busted, just keep retrying from the top
		i.schedule.RunIn(time.Minute, func() { i.start() })
	}

	i.issue()
}
