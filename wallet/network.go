package wallet

import (
	"encoding/json"
	"fmt"
	"os"
)

// NetworkConfig defines network parameters for a BSV network.
type NetworkConfig struct {
	Name           string   `json:"name"`
	AddressVersion byte     `json:"address_version"`
	P2SHVersion    byte     `json:"p2sh_version"`
	DefaultPort    uint16   `json:"default_port"`
	RPCPort        uint16   `json:"rpc_port"`
	DNSSeeds       []string `json:"seeds"`
	GenesisHash    string   `json:"genesis_hash"`
}

// Predefined network configurations.
var (
	MainNet = NetworkConfig{
		Name:           "mainnet",
		AddressVersion: 0x00,
		P2SHVersion:    0x05,
		DefaultPort:    8333,
		RPCPort:        8332,
		DNSSeeds:       []string{"seed.bitcoinsv.io", "seed.satoshisvision.network"},
		GenesisHash:    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
	}

	TestNet = NetworkConfig{
		Name:           "testnet",
		AddressVersion: 0x6f,
		P2SHVersion:    0xc4,
		DefaultPort:    18333,
		RPCPort:        18332,
		DNSSeeds:       []string{"testnet-seed.bitcoinsv.io"},
		GenesisHash:    "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
	}

	// TeraTestNet is experimental; parameters pending BSV official confirmation.
	TeraTestNet = NetworkConfig{
		Name:           "teratestnet",
		AddressVersion: 0x6f,
		P2SHVersion:    0xc4,
		DefaultPort:    0,
		RPCPort:        0,
		DNSSeeds:       []string{},
		GenesisHash:    "",
	}

	RegTest = NetworkConfig{
		Name:           "regtest",
		AddressVersion: 0x6f,
		P2SHVersion:    0xc4,
		DefaultPort:    18444,
		RPCPort:        18443,
		DNSSeeds:       nil,
		GenesisHash:    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
	}
)

// predefined maps network names to their configs.
var predefined = map[string]*NetworkConfig{
	"mainnet":     &MainNet,
	"testnet":     &TestNet,
	"teratestnet": &TeraTestNet,
	"regtest":     &RegTest,
}

// GetNetwork returns a predefined network by name.
// If the name is not predefined, it returns ErrInvalidNetwork.
func GetNetwork(name string) (*NetworkConfig, error) {
	if net, ok := predefined[name]; ok {
		return net, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrInvalidNetwork, name)
}

// LoadCustomNetwork loads a NetworkConfig from a JSON file.
func LoadCustomNetwork(path string) (*NetworkConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("wallet: failed to read network config: %w", err)
	}

	var config NetworkConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("wallet: failed to parse network config: %w", err)
	}

	if config.Name == "" {
		return nil, fmt.Errorf("wallet: network config must have a name")
	}

	return &config, nil
}
