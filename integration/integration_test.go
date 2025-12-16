//go:build integration

// Package integration contains an integration test with test-certs-site and Pebble
package integration

import "testing"

// TestIntegration runs pebble and test-certs-site together.
// It assumes `pebble` and `test-certs-site` are on the $PATH.
// There is a Dockerfile in the same directory as this test which can be used.
func TestIntegration(t *testing.T) {

}
