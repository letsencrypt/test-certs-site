// Package gorepotemplate provides nothing but an example function and
// a unit test.
package gorepotemplate

import (
	"fmt"
	"strings"
)

// Hello returns a greeting for the given name. All names will be converted to
// lowercase for the greeting. If no name is provided the greeting will be
// a simple "Hello".
func Hello(name string) string {
	if name == "" {
		return "Hello"
	}

	return fmt.Sprintf("Hello %s", strings.ToLower(name))
}
