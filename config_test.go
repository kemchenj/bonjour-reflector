package main

import (
	"os"
	"reflect"
	"sort"
	"testing"
)

var devices = map[macAddress]bonjourDevice{
	"00:14:22:01:23:45": bonjourDevice{OriginPool: 45, SharedPools: []uint16{42, 1042, 46}},
	"00:14:22:01:23:46": bonjourDevice{OriginPool: 46, SharedPools: []uint16{176, 148}},
	"00:14:22:01:23:47": bonjourDevice{OriginPool: 47, SharedPools: []uint16{1042, 1717, 13}},
}

func TestReadConfig(t *testing.T) {
	// Check that a valid config file is read adequately
	validTestConfigFile := "config_test.toml"
	computedCfg, err := readConfig(validTestConfigFile)
	expectedCfg := brconfig{
		NetInterface: "test0",
		Interfaces: []brInterface{
			{Name: "test0", Pool: 45},
			{Name: "test1", Pool: 46},
		},
		Devices: devices,
	}

	if err != nil {
		t.Errorf("Error in readConfig(): failed to read test config file %s", validTestConfigFile)
	} else if !reflect.DeepEqual(expectedCfg, computedCfg) {
		t.Error("Error in readConfig(): expected config does not match computed config")
	}

	// Check that a non-existant config file is handled adequately
	nonexistantConfigFile := "nonexistant_test.toml"
	computedCfg, err = readConfig(nonexistantConfigFile)
	if !reflect.DeepEqual(computedCfg, brconfig{}) {
		t.Error("Error in readConfig(): unexpected config returned for non-existant config file")
	}
	if !os.IsNotExist(err) {
		// if the error returned is not of type "file not found"
		t.Error("Error in readConfig(): wrong error returned for nonexistant config file")
	}
}

func TestMapByPool(t *testing.T) {
	computedResult := mapByPool(devices)
	// Sort slices to ensure that a different order does not make the test fail
	for _, slice := range computedResult {
		sort.Slice(slice, func(i, j int) bool { return slice[i] < slice[j] })
	}

	expectedResult := map[uint16]([]uint16){
		42:   []uint16{45},
		1042: []uint16{45, 47},
		46:   []uint16{45},
		176:  []uint16{46},
		148:  []uint16{46},
		13:   []uint16{47},
		1717: []uint16{47},
	}
	if !reflect.DeepEqual(computedResult, expectedResult) {
		t.Error("Error in mapByPool()")
	}
}

func TestBuildMirrorPeers(t *testing.T) {
	peers := buildMirrorPeers([][]uint16{{1, 10}, {100, 200, 300}})
	for _, slice := range peers {
		sort.Slice(slice, func(i, j int) bool { return slice[i] < slice[j] })
	}
	expected := map[uint16][]uint16{
		1:   {10},
		10:  {1},
		100: {200, 300},
		200: {100, 300},
		300: {100, 200},
	}
	if !reflect.DeepEqual(peers, expected) {
		t.Errorf("buildMirrorPeers() = %#v, want %#v", peers, expected)
	}
}

func TestMergeDedupeUint16(t *testing.T) {
	got := mergeDedupeUint16([]uint16{1, 2, 3}, []uint16{2, 4})
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	want := []uint16{1, 2, 3, 4}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mergeDedupeUint16() = %v, want %v", got, want)
	}
}
