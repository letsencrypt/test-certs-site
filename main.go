// Package main is the entry point to test-certs-site.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/letsencrypt/test-certs-site/acme"
	"github.com/letsencrypt/test-certs-site/certs"
	"github.com/letsencrypt/test-certs-site/config"
	"github.com/letsencrypt/test-certs-site/server"
	"github.com/letsencrypt/test-certs-site/storage"
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

	store, err := storage.New(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("creating storage: %w", err)
	}

	certManager, err := certs.New(context.Background(), cfg, store)
	if err != nil {
		return err
	}

	acmeClient, err := acme.New(cfg, store)
	if err != nil {
		return err
	}

	go acmeClient.Run()

	return server.Run(cfg, certManager.GetCertificate)
}

func main() {
	err := run(os.Args)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
