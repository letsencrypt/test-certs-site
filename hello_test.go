package gorepotemplate

import "testing"

// TestHello tests that the Hello function produces the expected greeting.
func TestHello(t *testing.T) {
	testCases := []struct {
		TestCaseName     string
		Name             string
		ExpectedGreeting string
	}{
		{
			TestCaseName:     "All lowercase name",
			Name:             "cpu",
			ExpectedGreeting: "Hello cpu",
		},
		{
			TestCaseName:     "All uppercase name",
			Name:             "CPU",
			ExpectedGreeting: "Hello cpu",
		},
		{
			TestCaseName:     "Mixed case name",
			Name:             "cPu",
			ExpectedGreeting: "Hello cpu",
		},
		{
			TestCaseName:     "No name",
			ExpectedGreeting: "Hello",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.TestCaseName, func(t *testing.T) {
			if greeting := Hello(tc.Name); greeting != tc.ExpectedGreeting {
				t.Errorf("hello(%q) returned %q not %q",
					tc.Name, greeting, tc.ExpectedGreeting)
			}
		})
	}
}
