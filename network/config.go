package network

import "fmt"

// RPCConfig holds the connection parameters for a BSV node's JSON-RPC interface.
type RPCConfig struct {
	URL      string `json:"url"`
	User     string `json:"user"`
	Password string `json:"password"`
	Network  string `json:"network"`
}

// NetworkPresets contains default RPC configurations for known networks.
// Mainnet is intentionally omitted to require explicit configuration.
var NetworkPresets = map[string]RPCConfig{
	"regtest": {URL: "http://localhost:18332", User: "bitfs", Password: "bitfs"},
	"testnet": {URL: "http://localhost:18332", User: "bitfs", Password: "bitfs"},
}

// ResolveConfig merges RPC configuration from three sources with decreasing priority:
//  1. CLI flags (highest priority)
//  2. Environment variables (BITFS_RPC_URL, BITFS_RPC_USER, BITFS_RPC_PASS)
//  3. Network presets (lowest priority, regtest/testnet only)
//
// For mainnet, explicit configuration is required -- there is no preset.
func ResolveConfig(flags *RPCConfig, env map[string]string, network string) (*RPCConfig, error) {
	result := RPCConfig{Network: network}

	// Layer 1: start with preset defaults if available.
	if preset, ok := NetworkPresets[network]; ok {
		result = preset
		result.Network = network
	}

	// Layer 2: environment variables override preset defaults.
	if env != nil {
		if v, ok := env["BITFS_RPC_URL"]; ok && v != "" {
			result.URL = v
		}
		if v, ok := env["BITFS_RPC_USER"]; ok && v != "" {
			result.User = v
		}
		if v, ok := env["BITFS_RPC_PASS"]; ok && v != "" {
			result.Password = v
		}
	}

	// Layer 3: CLI flags have highest priority.
	if flags != nil {
		if flags.URL != "" {
			result.URL = flags.URL
		}
		if flags.User != "" {
			result.User = flags.User
		}
		if flags.Password != "" {
			result.Password = flags.Password
		}
	}

	// Validate: URL must be set (mainnet has no preset, so this catches unconfigured mainnet).
	if result.URL == "" {
		return nil, fmt.Errorf("network: %s requires explicit RPC configuration (set --rpc-url, BITFS_RPC_URL, or config file)", network)
	}

	return &result, nil
}
