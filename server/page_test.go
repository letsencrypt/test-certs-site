package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/letsencrypt/test-certs-site/config"
)

var (
	customTextTemplate = `
Text Template
.Domain: {{ .Domain }}
.Info.IssuerCN: {{ .Info.IssuerCN }}
.Info.State: {{ .Info.State }}
`

	customHTMLTemplate = `
<h1>HTML Template</h1>
<p>.Domain: {{ .Domain }}</p>
<p>.Info.IssuerCN: {{ .Info.IssuerCN }}</p>
<p>.Info.State: {{ .Info.State }}</p>
`
)

func TestNewHandler(t *testing.T) {
	t.Parallel()

	testCfg := config.Config{
		Sites: []config.Site{
			{
				IssuerCN: "used car sales",
				Domains: config.Domains{
					Valid:   "valid.test",
					Expired: "expired.test",
					Revoked: "revoked.test",
				},
			},
		},
	}

	defaultHandler, err := newHandler(&testCfg)
	if err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()
	testTextTmpl := tmp + "/template.txt"
	testHTMLTmpl := tmp + "/template.html"

	err = os.WriteFile(testTextTmpl, []byte(customTextTemplate), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(testHTMLTmpl, []byte(customHTMLTemplate), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	testCfg.TextTemplate = testTextTmpl
	testCfg.HTMLTemplate = testHTMLTmpl
	customHandler, err := newHandler(&testCfg)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		domain  string
		handler handler
		url     string
		bodyHas []string
	}{
		{
			domain:  "valid.test",
			handler: defaultHandler,
			url:     "/?txt",
			bodyHas: []string{
				"# valid.test",
				"This test website, valid.test, is intended for",
				"The certificate is valid.",
			},
		},
		{
			domain:  "expired.test",
			handler: defaultHandler,
			url:     "/?html",
			bodyHas: []string{
				"<h1>expired.test</h1>",
				"This test website, expired.test, is intended for",
				"It is using a certificate issued by <code>used car sales</code>",
				"The certificate is expired.",
			},
		},
		{
			domain:  "revoked.test",
			handler: defaultHandler,
			url:     "/?txt",
			bodyHas: []string{
				"# revoked.test",
				"The certificate is revoked.",
			},
		},
		{
			domain:  "revoked.test",
			handler: customHandler,
			url:     "/?txt",
			bodyHas: []string{
				"Text Template",
				".Domain: revoked.test",
			},
		},
		{
			domain:  "expired.test",
			handler: customHandler,
			url:     "/?html",
			bodyHas: []string{
				"<h1>HTML Template</h1>",
				"<p>.Domain: expired.test</p>",
				"<p>.Info.IssuerCN: used car sales</p>",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.domain, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(http.MethodGet, test.url, nil)
			request.TLS = &tls.ConnectionState{
				ServerName: test.domain,
			}

			record := httptest.NewRecorder()

			test.handler.ServeHTTP(record, request)

			if record.Code != http.StatusOK {
				t.Errorf("got %d from handler instead of 200", record.Code)
			}

			for _, bodyHas := range test.bodyHas {
				if !strings.Contains(record.Body.String(), bodyHas) {
					t.Log(record.Body.String())
					t.Errorf("Body missing expected substring %q", bodyHas)
				}
			}
		})
	}
}
