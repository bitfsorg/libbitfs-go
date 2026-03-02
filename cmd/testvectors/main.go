// cmd/testvectors generates deterministic cross-language test vectors as JSON.
//
// These vectors are consumed by the TypeScript test suite (libbitfs-ts) to
// verify binary-level compatibility between Go and TypeScript implementations.
//
// Usage: go run ./cmd/testvectors/ > vectors.json
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/bsv-blockchain/go-sdk/compat/bip39"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/bitfsorg/libbitfs-go/method42"
	"github.com/bitfsorg/libbitfs-go/metanet"
	"github.com/bitfsorg/libbitfs-go/revshare"
	"github.com/bitfsorg/libbitfs-go/spv"
	"github.com/bitfsorg/libbitfs-go/wallet"
)

// Vectors holds all cross-language test vectors.
type Vectors struct {
	Method42ECDH      ECDHVector       `json:"method42_ecdh"`
	Method42DeriveAES DeriveAESVector  `json:"method42_derive_aes_key"`
	Method42KeyHash   KeyHashVector    `json:"method42_key_hash"`
	WalletDerive      WalletVector     `json:"wallet_derive"`
	MetanetChildEntry ChildEntryVector `json:"metanet_child_entry"`
	RevshareRegistry  RegistryVector   `json:"revshare_registry"`
	SPVDoubleHash     DoubleHashVector `json:"spv_double_hash"`
}

type ECDHVector struct {
	PrivKeyHex      string `json:"privkey_hex"`
	PubKeyHex       string `json:"pubkey_hex"`
	SharedSecretHex string `json:"shared_secret_hex"`
}

type DeriveAESVector struct {
	SharedSecretHex string `json:"shared_secret_hex"`
	KeyHashHex      string `json:"key_hash_hex"`
	AESKeyHex       string `json:"aes_key_hex"`
}

type KeyHashVector struct {
	PlaintextHex string `json:"plaintext_hex"`
	KeyHashHex   string `json:"key_hash_hex"`
}

type WalletVector struct {
	Mnemonic  string `json:"mnemonic"`
	SeedHex   string `json:"seed_hex"`
	Path      string `json:"path"`
	PubKeyHex string `json:"pubkey_hex"`
}

type ChildEntryJSON struct {
	Index    uint32 `json:"index"`
	Name     string `json:"name"`
	Type     int32  `json:"type"`
	PubKey   string `json:"pubkey_hex"`
	Hardened bool   `json:"hardened"`
}

type ChildEntryVector struct {
	Entry         ChildEntryJSON `json:"entry"`
	SerializedHex string         `json:"serialized_hex"`
}

type RegistryEntryJSON struct {
	AddressHex string `json:"address_hex"`
	Share      uint64 `json:"share"`
}

type RegistryStateJSON struct {
	NodeIDHex   string              `json:"node_id_hex"`
	TotalShares uint64              `json:"total_shares"`
	Entries     []RegistryEntryJSON `json:"entries"`
	ModeFlags   uint8               `json:"mode_flags"`
}

type RegistryVector struct {
	State         RegistryStateJSON `json:"state"`
	SerializedHex string            `json:"serialized_hex"`
}

type DoubleHashVector struct {
	DataHex string `json:"data_hex"`
	HashHex string `json:"hash_hex"`
}

func must[T any](v T, err error) T {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
	return v
}

func main() {
	v := Vectors{}

	// --- method42_ecdh ---
	// Use a well-known private key: scalar = 2
	privBytes := padTo32(big.NewInt(2).Bytes())
	privKey, _ := ec.PrivateKeyFromBytes(privBytes)
	pubKey := privKey.PubKey()

	sharedSecret := must(method42.ECDH(privKey, pubKey))
	v.Method42ECDH = ECDHVector{
		PrivKeyHex:      hex.EncodeToString(privBytes),
		PubKeyHex:       hex.EncodeToString(pubKey.ToDER()),
		SharedSecretHex: hex.EncodeToString(sharedSecret),
	}

	// --- method42_derive_aes_key ---
	// Use a known shared secret (32 bytes of 0x01) and known key_hash
	sharedX := make([]byte, 32)
	for i := range sharedX {
		sharedX[i] = 0x01
	}
	plaintext := []byte("hello bitfs")
	keyHash := method42.ComputeKeyHash(plaintext)
	aesKey := must(method42.DeriveAESKey(sharedX, keyHash))

	v.Method42DeriveAES = DeriveAESVector{
		SharedSecretHex: hex.EncodeToString(sharedX),
		KeyHashHex:      hex.EncodeToString(keyHash),
		AESKeyHex:       hex.EncodeToString(aesKey),
	}

	// --- method42_key_hash ---
	plaintextBytes := []byte{0xde, 0xad, 0xbe, 0xef}
	kh := method42.ComputeKeyHash(plaintextBytes)
	v.Method42KeyHash = KeyHashVector{
		PlaintextHex: hex.EncodeToString(plaintextBytes),
		KeyHashHex:   hex.EncodeToString(kh),
	}

	// --- wallet_derive ---
	// Use the standard "abandon" mnemonic for determinism
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	seed := must(bip39.NewSeedWithErrorChecking(mnemonic, ""))
	w := must(wallet.NewWallet(seed, &wallet.MainNet))
	feeKey := must(w.DeriveFeeKey(0, 0))

	v.WalletDerive = WalletVector{
		Mnemonic:  mnemonic,
		SeedHex:   hex.EncodeToString(seed),
		Path:      feeKey.Path,
		PubKeyHex: hex.EncodeToString(feeKey.PublicKey.ToDER()),
	}

	// --- metanet_child_entry ---
	// Build a known ChildEntry and serialize it
	childPubKey := make([]byte, 33)
	childPubKey[0] = 0x02
	for i := 1; i < 33; i++ {
		childPubKey[i] = byte(i)
	}
	entry := &metanet.ChildEntry{
		Index:    42,
		Name:     "test.txt",
		Type:     metanet.NodeTypeFile,
		PubKey:   childPubKey,
		Hardened: true,
	}
	serialized := localSerializeChildEntry(entry)

	v.MetanetChildEntry = ChildEntryVector{
		Entry: ChildEntryJSON{
			Index:    entry.Index,
			Name:     entry.Name,
			Type:     int32(entry.Type),
			PubKey:   hex.EncodeToString(entry.PubKey),
			Hardened: entry.Hardened,
		},
		SerializedHex: hex.EncodeToString(serialized),
	}

	// --- revshare_registry ---
	nodeID := [32]byte{}
	for i := range nodeID {
		nodeID[i] = byte(i)
	}
	addr1 := [20]byte{}
	for i := range addr1 {
		addr1[i] = byte(0xa0 + i)
	}
	addr2 := [20]byte{}
	for i := range addr2 {
		addr2[i] = byte(0xb0 + i)
	}

	state := &revshare.RegistryState{
		NodeID:      nodeID,
		TotalShares: 10000,
		Entries: []revshare.RevShareEntry{
			{Address: addr1, Share: 6000},
			{Address: addr2, Share: 4000},
		},
		ModeFlags: 0x01, // ISO active
	}
	regData := must(revshare.SerializeRegistry(state))

	regEntries := make([]RegistryEntryJSON, len(state.Entries))
	for i, e := range state.Entries {
		regEntries[i] = RegistryEntryJSON{
			AddressHex: hex.EncodeToString(e.Address[:]),
			Share:      e.Share,
		}
	}
	v.RevshareRegistry = RegistryVector{
		State: RegistryStateJSON{
			NodeIDHex:   hex.EncodeToString(state.NodeID[:]),
			TotalShares: state.TotalShares,
			Entries:     regEntries,
			ModeFlags:   state.ModeFlags,
		},
		SerializedHex: hex.EncodeToString(regData),
	}

	// --- spv_double_hash ---
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	dhash := spv.DoubleHash(data)
	v.SPVDoubleHash = DoubleHashVector{
		DataHex: hex.EncodeToString(data),
		HashHex: hex.EncodeToString(dhash),
	}

	// Output JSON
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "JSON encode error: %v\n", err)
		os.Exit(1)
	}
}

// padTo32 zero-pads a byte slice to 32 bytes (big-endian).
func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[:32]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

// localSerializeChildEntry replicates the unexported metanet.serializeChildEntry.
// Format: index(4B LE) || nameLen(2B LE) || name || type(4B LE) || pubkeyLen(1B) || pubkey || hardened(1B)
func localSerializeChildEntry(entry *metanet.ChildEntry) []byte {
	nameBytes := []byte(entry.Name)
	size := 4 + 2 + len(nameBytes) + 4 + 1 + len(entry.PubKey) + 1
	buf := make([]byte, size)
	offset := 0

	// Index (4B LE)
	binary.LittleEndian.PutUint32(buf[offset:], entry.Index)
	offset += 4

	// Name length (2B LE) + name
	binary.LittleEndian.PutUint16(buf[offset:], uint16(len(nameBytes)))
	offset += 2
	copy(buf[offset:], nameBytes)
	offset += len(nameBytes)

	// Type (4B LE)
	binary.LittleEndian.PutUint32(buf[offset:], uint32(entry.Type))
	offset += 4

	// PubKey length (1B) + pubkey
	buf[offset] = byte(len(entry.PubKey))
	offset++
	copy(buf[offset:], entry.PubKey)
	offset += len(entry.PubKey)

	// Hardened flag (1B)
	if entry.Hardened {
		buf[offset] = 1
	} else {
		buf[offset] = 0
	}

	return buf
}
