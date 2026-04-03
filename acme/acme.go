// Package acme handles issuing certificates via ACME
package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"log/slog"
	mathrand "math/rand/v2"
	"net/http"
	"time"

	legoAcme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"

	"github.com/letsencrypt/test-certs-site/certs"
	"github.com/letsencrypt/test-certs-site/config"
	"github.com/letsencrypt/test-certs-site/scheduler"
	"github.com/letsencrypt/test-certs-site/storage"
)

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

func setupLego(cfg *config.Config, store *storage.Storage, user legoUser) (*lego.Client, error) {
	// Lego users can configure a custom logger by setting it in this global.
	log.Logger = slog.NewLogLogger(slog.Default().Handler(), slog.LevelInfo)

	// Try to load an existing ACME account
	accountURI, acctKey, err := store.ReadACME(cfg.ACME.Directory)
	if err != nil {
		// No account, need to make a new key
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
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

	client, err := newClient(&user, cfg.ACME.Directory)
	if err != nil {
		return nil, err
	}

	if user.reg != nil && !checkRegistration(&user, client, cfg) {
		// We have an account, but the CA doesn't know about it. Reset user and client and re-register
		user.reg = nil
		client, err = newClient(&user, cfg.ACME.Directory)
		if err != nil {
			return nil, err
		}
	}

	if user.reg == nil {
		err = register(&user, client, cfg, store)
		if err != nil {
			return nil, err
		}
	}

	return client, nil
}

func newClient(user *legoUser, directory string) (*lego.Client, error) {
	legoCfg := lego.NewConfig(user)
	legoCfg.CADirURL = directory
	legoCfg.UserAgent = "test-certs-site/1.0"

	return lego.NewClient(legoCfg)
}

func register(user *legoUser, client *lego.Client, cfg *config.Config, store *storage.Storage) error {
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

	return nil
}

// checkRegistration calls the ACME server to see if this account exists.
func checkRegistration(user *legoUser, client *lego.Client, cfg *config.Config) bool {
	_, queryErr := client.Registration.QueryRegistration()
	if queryErr != nil {
		var prob *legoAcme.ProblemDetails
		if errors.As(queryErr, &prob) && prob.Type == "urn:ietf:params:acme:error:accountDoesNotExist" {
			// Account is missing from the server.
			slog.Warn("ACME account missing from server, registering new account",
				slog.String("directory", cfg.ACME.Directory),
				slog.String("accountURI", user.reg.URI))
		} else {
			slog.Warn("Got unexpected error while querying ACME account",
				slog.String("directory", cfg.ACME.Directory),
				slogErr(queryErr))
		}

		return false
	}

	slog.Info("Existing ACME account found", slog.String("accountURI", user.reg.URI))

	return true
}

// New sets up the ACME client, registering it with the ACME server if one isn't present.
func New(cfg *config.Config, store *storage.Storage, schedule *scheduler.Schedule, manager *certs.CertManager) error {
	var user legoUser

	client, err := setupLego(cfg, store, user)
	if err != nil {
		return err
	}

	crlClient := &http.Client{
		Timeout: time.Minute,
	}

	crlCheckInterval := time.Duration(cfg.CRLCheckInterval)
	if crlCheckInterval == 0 {
		// An hour is a reasonable approximation of how long it might take for a new CRL to be issued.
		crlCheckInterval = time.Hour
	}

	revokeDelay := time.Duration(cfg.RevokeDelay)
	if revokeDelay == 0 {
		// 25 hours is long enough for CRLite and Windows CRL caches, including 1h backdating.
		revokeDelay = 25 * time.Hour //nolint:mnd
	}

	for _, site := range cfg.Sites {
		for domain, c := range map[string]checker{
			site.Domains.Valid: &valid{
				ari:    client.Certificate,
				logger: slog.With(slog.String("domain", site.Domains.Valid)),
			},
			site.Domains.Revoked: &revoked{
				http:          crlClient,
				logger:        slog.With(slog.String("domain", site.Domains.Revoked)),
				checkInterval: crlCheckInterval,
				delay:         revokeDelay,
			},
			site.Domains.Expired: expired{},
		} {
			i := issuer{
				checker: c,

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

			// Start each issuer within the next minute, spread out so they don't all run together
			delay := time.Duration(mathrand.Int64N(int64(time.Minute))) //nolint:gosec // Not security-sensitive use
			schedule.RunIn(delay, i.start)
		}
	}

	return client.Challenge.SetTLSALPN01Provider(manager)
}
