package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"strings"

	"github.com/pelletier/go-toml"
)

type macAddress string

type brconfig struct {
	NetInterface string                       `toml:"net_interface"`
	Interfaces   []brInterface                `toml:"interfaces"`
	Devices      map[macAddress]bonjourDevice `toml:"devices"`
	MirrorGroups [][]uint16                   `toml:"mirror_groups"`
}

type brInterface struct {
	Name string `toml:"name"`
	Pool uint16 `toml:"pool"`
}

type bonjourDevice struct {
	OriginPool  uint16   `toml:"origin_pool"`
	SharedPools []uint16 `toml:"shared_pools"`
}

func readConfig(path string) (cfg brconfig, err error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return brconfig{}, err
	}
	err = toml.Unmarshal(content, &cfg)
	return cfg, err
}

func (cfg *brconfig) validateAndNormalize() error {
	mapped := len(cfg.Interfaces) > 0
	if !mapped && strings.TrimSpace(cfg.NetInterface) == "" {
		return fmt.Errorf("set net_interface or configure at least one entry in interfaces")
	}

	pools := make(map[uint16]struct{}, len(cfg.Interfaces))
	names := make(map[string]struct{}, len(cfg.Interfaces))
	for i, intf := range cfg.Interfaces {
		if strings.TrimSpace(intf.Name) == "" {
			return fmt.Errorf("interfaces[%d].name is required", i)
		}
		if _, ok := names[intf.Name]; ok {
			return fmt.Errorf("interfaces[%d].name %q is already in use", i, intf.Name)
		}
		if intf.Pool == 0 {
			return fmt.Errorf("interfaces[%d].pool must be nonzero", i)
		}
		if _, ok := pools[intf.Pool]; ok {
			return fmt.Errorf("interfaces[%d].pool %d is already in use", i, intf.Pool)
		}
		pools[intf.Pool] = struct{}{}
		names[intf.Name] = struct{}{}
	}

	validatePool := func(pool uint16) error {
		if mapped {
			if _, ok := pools[pool]; !ok {
				return fmt.Errorf("pool %d is not defined in interfaces", pool)
			}
		} else if pool == 0 || pool > 4094 {
			return fmt.Errorf("VLAN ID %d is outside 1–4094", pool)
		}
		return nil
	}

	for i, group := range cfg.MirrorGroups {
		for j, pool := range group {
			if err := validatePool(pool); err != nil {
				return fmt.Errorf("mirror_groups[%d][%d]: %w", i, j, err)
			}
		}
	}

	if len(cfg.Devices) == 0 {
		return nil
	}
	devices := make(map[macAddress]bonjourDevice, len(cfg.Devices))
	for key, device := range cfg.Devices {
		mac, err := net.ParseMAC(string(key))
		if err != nil || len(mac) != 6 {
			return fmt.Errorf("devices[%q]: expected a 6-byte MAC address", key)
		}
		normalized := macAddress(mac.String())
		if _, ok := devices[normalized]; ok {
			return fmt.Errorf("devices[%q]: duplicate MAC address %s", key, normalized)
		}
		if err := validatePool(device.OriginPool); err != nil {
			return fmt.Errorf("devices[%q].origin_pool: %w", key, err)
		}
		for i, pool := range device.SharedPools {
			if err := validatePool(pool); err != nil {
				return fmt.Errorf("devices[%q].shared_pools[%d]: %w", key, i, err)
			}
		}
		devices[normalized] = device
	}
	cfg.Devices = devices
	return nil
}

func mapByPool(devices map[macAddress]bonjourDevice) map[uint16]([]uint16) {
	seen := make(map[uint16]map[uint16]bool)
	poolsMap := make(map[uint16]([]uint16))
	for _, device := range devices {
		for _, pool := range device.SharedPools {
			if _, ok := seen[pool]; !ok {
				seen[pool] = make(map[uint16]bool)
			}
			if _, ok := seen[pool][device.OriginPool]; !ok {
				seen[pool][device.OriginPool] = true
				poolsMap[pool] = append(poolsMap[pool], device.OriginPool)
			}
		}
	}
	return poolsMap
}

// buildMirrorPeers maps each VLAN ID to the other VLANs in the same mirror group.
// A packet arriving on VLAN v is forwarded to every peer in mirrorPeers[v] (never v itself).
func buildMirrorPeers(groups [][]uint16) map[uint16][]uint16 {
	mirrorPeers := make(map[uint16]map[uint16]struct{})
	for _, g := range groups {
		for _, v := range g {
			if mirrorPeers[v] == nil {
				mirrorPeers[v] = make(map[uint16]struct{})
			}
			for _, w := range g {
				if w != v {
					mirrorPeers[v][w] = struct{}{}
				}
			}
		}
	}
	out := make(map[uint16][]uint16)
	for v, peers := range mirrorPeers {
		for p := range peers {
			out[v] = append(out[v], p)
		}
	}
	return out
}

func mergeDedupeUint16(a, b []uint16) []uint16 {
	seen := make(map[uint16]struct{})
	var out []uint16
	for _, x := range a {
		if _, ok := seen[x]; !ok {
			seen[x] = struct{}{}
			out = append(out, x)
		}
	}
	for _, x := range b {
		if _, ok := seen[x]; !ok {
			seen[x] = struct{}{}
			out = append(out, x)
		}
	}
	return out
}
