// Package main is the entry point to test-certs-site.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/letsencrypt/test-certs-site/config"
	"github.com/letsencrypt/test-certs-site/server"
)

func run(args []string) error {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	fs := flag.NewFlagSet(args[0], flag.ExitOnError)
	cfgPath := fs.String("config", "config.json", "path to json config file")

	err := fs.Parse(args[1:])
	if err != nil {
		return fmt.Errorf("parsing command line: %w", err)
	}

	if cfgPath == nil {
		return fmt.Errorf("no config file specified")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// This is just a temporary placeholder, using a single static test certificate
	// This will normally be provided by the key storage part of this program
	cert := os.Getenv("TEST_CERT")
	key := os.Getenv("TEST_KEY")
	temporaryStaticCert, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return fmt.Errorf("loading temporary certificate: %w", err)
	}
	todoGetCert := func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &temporaryStaticCert, nil
	}

	return server.Run(cfg.ListenAddr, todoGetCert)
}

func main() {
	err := run(os.Args)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
