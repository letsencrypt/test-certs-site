// Package main is the entry point to test-certs-site.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/letsencrypt/test-certs-site/config"
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

	slog.Info("Loaded configuration! This program doesn't do anything yet.", slog.String("configFile", *cfgPath), slog.Any("config", cfg))

	return nil
}

func main() {
	err := run(os.Args)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
