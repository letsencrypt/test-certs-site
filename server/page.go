package server

import (
	_ "embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/letsencrypt/test-certs-site/config"
)

//go:embed page.html
var htmlTemplate string

//go:embed page.txt
var textTemplate string

type handler struct {
	htmlTemplate *template.Template
	textTemplate *template.Template
	domains      map[string]info
}

type info struct {
	IssuerCN string
	State    string
}

func newHandler(cfg *config.Config) handler {
	domains := make(map[string]info)

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
		htmlTemplate: template.Must(template.New("homePage").Parse(htmlTemplate)),
		textTemplate: template.Must(template.New("homePage").Parse(textTemplate)),
		domains:      domains,
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
		slog.Warn("No info for domain", slog.String("sni", r.TLS.ServerName))

		return
	}

	tmpl, contentType := h.getTmpl(r.URL.RawQuery, "txt")

	w.Header().Set("Content-Type", contentType+"; charset=utf-8")

	err := tmpl.Execute(w, templateData{
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

// getTmpl returns the correct template based on the URL query, and HTTP Accept header
func (h handler) getTmpl(query, acceptHeader string) (*template.Template, string) {
	if query == "txt" {
		return h.textTemplate, "text/plain"
	}

	if query == "html" {
		return h.htmlTemplate, "text/html"
	}

	if strings.Contains(acceptHeader, "text/html") {
		return h.htmlTemplate, "text/html"
	}

	return h.textTemplate, "text/plain"
}
