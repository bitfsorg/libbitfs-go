package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkPresets(t *testing.T) {
	tests := []struct {
		name    string
		network string
		url     string
		user    string
	}{
		{"regtest defaults", "regtest", "http://localhost:18332", "bitfs"},
		{"testnet defaults", "testnet", "http://localhost:18333", "bitfs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			preset, ok := NetworkPresets[tt.network]
			require.True(t, ok, "preset should exist for %s", tt.network)
			assert.Equal(t, tt.url, preset.URL)
			assert.Equal(t, tt.user, preset.User)
		})
	}
}

func TestMainnetHasNoPreset(t *testing.T) {
	_, ok := NetworkPresets["mainnet"]
	assert.False(t, ok, "mainnet should not have a default preset")
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

func TestResolveConfigPartialFlags(t *testing.T) {
	flags := &RPCConfig{URL: "http://partial:8332"}
	cfg, err := ResolveConfig(flags, nil, "regtest")
	require.NoError(t, err)
	assert.Equal(t, "http://partial:8332", cfg.URL)
	assert.Equal(t, "bitfs", cfg.User)     // from preset
	assert.Equal(t, "bitfs", cfg.Password) // from preset
}
