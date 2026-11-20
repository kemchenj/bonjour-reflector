package main

import (
	"os"
	"testing"
)

func TestReadConfig(t *testing.T) {
	got, err := readConfig("config_test.toml")
	if err != nil || got != [2]string{"test0", "test1"} {
		t.Fatalf("readConfig() = %v, %v", got, err)
	}
	if _, err := readConfig("nonexistant_test.toml"); !os.IsNotExist(err) {
		t.Fatalf("expected file not found, got %v", err)
	}
}
