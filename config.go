package main

import (
	"io/ioutil"

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
