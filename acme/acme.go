// Package acme handles issuing certificates via ACME
package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	mathrand "math/rand/v2"
	"net/http"
	"time"

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
			site.Domains.Valid: &valid{
				client: client,
				logger: slog.With(slog.String("domain", site.Domains.Valid)),
			},
			site.Domains.Revoked: &revoked{
				http:          http.DefaultClient,
				logger:        slog.With(slog.String("domain", site.Domains.Revoked)),
				checkInterval: time.Hour, // TODO: We might want to make this configurable in the future
			},
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
			delay := time.Duration(mathrand.Int64N(int64(time.Minute))) //nolint:gosec // Not security-sensitive
			schedule.RunIn(delay, i.start)
		}
	}

	return nil
}
