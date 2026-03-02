// Copyright (c) 2024 The BitFS developers
// Use of this source code is governed by the Open BSV License v5
// that can be found in the LICENSE file.

package config

import "errors"

var (
	// ErrInvalidNetwork indicates the network name is not recognized.
	ErrInvalidNetwork = errors.New("config: invalid network (must be \"mainnet\", \"testnet\", or \"regtest\")")

	// ErrInvalidListenAddr indicates the listen address is malformed.
	ErrInvalidListenAddr = errors.New("config: invalid listen address")

	// ErrInvalidLogLevel indicates the log level is not recognized.
	ErrInvalidLogLevel = errors.New("config: invalid log level (must be \"debug\", \"info\", \"warn\", or \"error\")")

	// ErrEmptyDataDir indicates the data directory path is empty.
	ErrEmptyDataDir = errors.New("config: data directory must not be empty")

	// ErrConfigNotFound indicates the configuration file does not exist.
	ErrConfigNotFound = errors.New("config: configuration file not found")

	// ErrInvalidConfigLine indicates a line in the config file is malformed.
	ErrInvalidConfigLine = errors.New("config: invalid configuration line")
)
