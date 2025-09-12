// Package main is the entry point to test-certs-site.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
)

// Config is the structure of the JSON configuration file.
type Config struct{}

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

	cfgBytes, err := os.ReadFile(*cfgPath)
	if err != nil {
		return fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config

	err = json.Unmarshal(cfgBytes, &cfg)
	if err != nil {
		return fmt.Errorf("parsing config file %s: %w", *cfgPath, err)
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
