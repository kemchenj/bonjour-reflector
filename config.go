package main

import (
	"fmt"
	"strings"

	"github.com/pelletier/go-toml"
)

func readConfig(path string) ([2]string, error) {
	tree, err := toml.LoadFile(path)
	if err != nil {
		return [2]string{}, err
	}
	for _, key := range tree.Keys() {
		if key != "interfaces" {
			return [2]string{}, fmt.Errorf("unsupported config key %q; only interfaces is accepted", key)
		}
	}
	var cfg struct {
		Interfaces []string `toml:"interfaces"`
	}
	if err := tree.Unmarshal(&cfg); err != nil {
		return [2]string{}, err
	}
	if len(cfg.Interfaces) != 2 || strings.TrimSpace(cfg.Interfaces[0]) == "" || strings.TrimSpace(cfg.Interfaces[1]) == "" || cfg.Interfaces[0] == cfg.Interfaces[1] {
		return [2]string{}, fmt.Errorf("interfaces must contain two distinct, nonempty interface names")
	}
	return [2]string(cfg.Interfaces), nil
}
