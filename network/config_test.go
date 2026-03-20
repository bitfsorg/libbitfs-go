package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkPresets(t *testing.T) {
	preset, ok := NetworkPresets["regtest"]
	require.True(t, ok, "preset should exist for regtest")
	assert.Equal(t, "http://localhost:18332", preset.URL)
	assert.Equal(t, "bitfs", preset.User)
}

func TestMainnetAndTestnetHaveNoPreset(t *testing.T) {
	_, ok := NetworkPresets["mainnet"]
	assert.False(t, ok, "mainnet should not have a default preset")
	_, ok = NetworkPresets["testnet"]
	assert.False(t, ok, "testnet should not have a default preset (uses WoC+ARC)")
}

func TestResolveConfigFlagsOverrideAll(t *testing.T) {
	flags := &RPCConfig{URL: "http://custom:9999", User: "me", Password: "secret"}
	cfg, err := ResolveConfig(flags, nil, "regtest")
	require.NoError(t, err)
	assert.Equal(t, "http://custom:9999", cfg.URL)
	assert.Equal(t, "me", cfg.User)
	assert.Equal(t, "secret", cfg.Password)
}

func TestResolveConfigEnvOverridesPreset(t *testing.T) {
	env := map[string]string{
		"BITFS_RPC_URL":  "http://env-node:18332",
		"BITFS_RPC_USER": "envuser",
	}
	cfg, err := ResolveConfig(nil, env, "regtest")
	require.NoError(t, err)
	assert.Equal(t, "http://env-node:18332", cfg.URL)
	assert.Equal(t, "envuser", cfg.User)
	assert.Equal(t, "bitfs", cfg.Password) // falls through to preset
}

func TestResolveConfigPresetFallback(t *testing.T) {
	cfg, err := ResolveConfig(nil, nil, "regtest")
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:18332", cfg.URL)
	assert.Equal(t, "bitfs", cfg.User)
	assert.Equal(t, "bitfs", cfg.Password)
}

func TestResolveConfigMainnetRequiresExplicit(t *testing.T) {
	_, err := ResolveConfig(nil, nil, "mainnet")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mainnet")
}

func TestResolveConfigTestnetRequiresExplicit(t *testing.T) {
	_, err := ResolveConfig(nil, nil, "testnet")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "testnet")
}

func TestResolveConfigPartialFlags(t *testing.T) {
	flags := &RPCConfig{URL: "http://partial:8332"}
	cfg, err := ResolveConfig(flags, nil, "regtest")
	require.NoError(t, err)
	assert.Equal(t, "http://partial:8332", cfg.URL)
	assert.Equal(t, "bitfs", cfg.User)     // from preset
	assert.Equal(t, "bitfs", cfg.Password) // from preset
}
