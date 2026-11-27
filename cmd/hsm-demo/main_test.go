package main

import "testing"

func TestDemoRuns(t *testing.T) {
	if err := run(); err != nil {
		t.Fatal(err)
	}
}
