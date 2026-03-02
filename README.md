# libbitfs-go

Shared core library for the BitFS ecosystem. Used by `bitfs`, `metanet`, `den-explorer`, and `git-remote-bitfs`.

Module: `github.com/bitfsorg/libbitfs-go`

## Packages

| Package | Purpose |
|---|---|
| method42 | ECDH encryption engine (AES-256-GCM, Private/Free/Paid access modes) |
| wallet | HD wallet (BIP44 m/44'/236'/account'/chain/index, Argon2id seed encryption) |
| vault | Unified file system state management + file locking |
| tx | Metanet transaction builder (MutationBatch: atomic multi-op transactions) |
| metanet | Metanet DAG + Unix file system operations (directories, links, TLV, Merkle root) |
| spv | SPV light client (block headers, Merkle proof verification, PoW validation) |
| storage | Content-addressed store (SHA256, hash-sharded directories, compression, chunking) |
| network | Blockchain service interface (BlockchainService, RPCClient, SPVClient, presets) |
| x402 | HTTP 402 payment protocol (X-Price/X-Invoice-Id headers, HTLC, payment verification) |
| paymail | Paymail protocol (.well-known/bsvalias discovery, PKI endpoint resolution) |
| revshare | Revenue sharing (registry, distribution algorithm, share conservation) |
| config | Configuration file parser (key=value format) |

## Usage

```go
import "github.com/bitfsorg/libbitfs-go/method42"
```

For local development with `bitfs` or other consumers, use a `replace` directive:

```
replace github.com/bitfsorg/libbitfs-go => ../libbitfs-go
```

## Dependencies

- `github.com/bsv-blockchain/go-sdk` — BSV primitives
- `golang.org/x/crypto` — Argon2id, HKDF
- `github.com/stretchr/testify` — Testing

## License

OpenBSV License
