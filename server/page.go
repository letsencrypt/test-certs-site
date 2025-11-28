package server

import (
	_ "embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/letsencrypt/test-certs-site/config"
)

//go:embed page.html
var pageTemplate string

type handler struct {
	template *template.Template
	domains  map[string]info
}

type info struct {
	IssuerCN string
	State    string
}

func newHandler(cfg *config.Config) handler {
	domains := make(map[string]info, 3*len(cfg.Sites))

	for _, site := range cfg.Sites {
		domains[site.Domains.Valid] = info{
			IssuerCN: site.IssuerCN,
			State:    "valid",
		}
		domains[site.Domains.Revoked] = info{
			IssuerCN: site.IssuerCN,
			State:    "revoked",
		}
		domains[site.Domains.Expired] = info{
			IssuerCN: site.IssuerCN,
			State:    "expired",
		}
	}

	return handler{
		template: template.Must(template.New("homePage").Parse(pageTemplate)),
		domains:  domains,
	}
}

type templateData struct {
	Domain string
	Info   info
}

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != "/" {
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, "404 Not Found")

		return
	}

	info, ok := h.domains[r.TLS.ServerName]
	if !ok {
		// This shouldn't happen, but make sure we don't try to render a template if we don't have data for it.
		w.WriteHeader(http.StatusNotFound)
		slog.Warn("No info for domain", r.TLS.ServerName)

		return
	}

	err := h.template.Execute(w, templateData{
		Domain: r.TLS.ServerName,
		Info:   info,
	})
	if err != nil {
		_, _ = fmt.Fprintf(w, "Failed to render page")
		slog.Warn("Error rendering template",
			slog.String("sni", r.TLS.ServerName),
			slog.String("error", err.Error()))
	}
}
