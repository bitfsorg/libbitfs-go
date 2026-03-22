package vault

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/bitfsorg/libbitfs-go/config"
	"github.com/bitfsorg/libbitfs-go/network"
	"github.com/bitfsorg/libbitfs-go/spv"
	"github.com/bitfsorg/libbitfs-go/storage"
	"github.com/bitfsorg/libbitfs-go/tx"
	"github.com/bitfsorg/libbitfs-go/wallet"
)

// Vault is the shared business logic layer. CLI commands, shell REPL,
// and daemon adapters all call Vault methods to perform filesystem operations.
//
// CONCURRENCY: All mutating methods (Put, Mkdir, Remove, Move, Copy, Link,
// Sell, Encrypt, Decrypt) acquire an exclusive file-level flock via
// withWriteLock, which serializes access across both goroutines and processes.
// Read-only methods (VerifyTx, ResolveVaultIndex, IsOnline) may be called
// concurrently. Do not call DeriveChangeAddr, AllocateFeeUTXO, or
// AllocateFeeUTXOWithState outside of withWriteLock. [Audit fix H-1]

// ErrInsufficientFunds is returned when no fee UTXO has enough balance
// for the requested operation. Callers can use errors.Is to detect this
// and show funding guidance (e.g. BSV purchase links).
var ErrInsufficientFunds = errors.New("insufficient funds")

type Vault struct {
	Wallet   *wallet.Wallet
	WState   *wallet.WalletState
	Store    *storage.FileStore
	Resolver *storage.ContentResolver // multi-source content fetcher
	State    *LocalState
	DataDir  string
	Chain    network.BlockchainService // optional; nil = offline mode
	SPV      *network.SPVClient        // nil until InitSPV; requires Chain != nil
	SPVStore *spv.BoltStore            // nil until InitSPV; closed by Close()

	// verifyOnce deduplicates concurrent VerifyTx calls for the same txid,
	// preventing redundant network requests. [Audit fix M-9]
	verifyOnce sync.Map // txid string -> *verifyCall
}

// Result holds the output of a vault operation.
type Result struct {
	TxHex   string // signed transaction hex (empty if build-only)
	TxID    string // transaction ID hex
	Message string // human-readable summary
	NodePub string // created/updated node pubkey hex
}

// New creates a new Vault from a data directory.
func New(dataDir, password string) (*Vault, error) {
	// Load wallet.
	walletPath := filepath.Join(dataDir, "wallet.enc")
	encrypted, err := readFile(walletPath)
	if err != nil {
		return nil, fmt.Errorf("vault: read wallet: %w", err)
	}

	if password == "" {
		return nil, fmt.Errorf("vault: password is required")
	}

	seed, err := wallet.DecryptSeed(encrypted, password)
	if err != nil {
		return nil, fmt.Errorf("vault: decrypt wallet: %w", err)
	}

	// Load network from config file; default to mainnet if config is missing.
	netCfg := &wallet.MainNet
	if cfg, cfgErr := config.LoadConfig(config.ConfigPath(dataDir)); cfgErr == nil {
		if resolved, netErr := wallet.GetNetwork(cfg.Network); netErr == nil {
			netCfg = resolved
		}
	}

	w, err := wallet.NewWallet(seed, netCfg)
	if err != nil {
		return nil, fmt.Errorf("vault: create wallet: %w", err)
	}

	statePath := filepath.Join(dataDir, "state.json")
	wState, err := loadWalletState(statePath)
	if err != nil {
		return nil, fmt.Errorf("vault: load wallet state: %w", err)
	}

	// Initialize content store.
	storeDir := filepath.Join(dataDir, "storage")
	store, err := storage.NewFileStore(storeDir)
	if err != nil {
		return nil, fmt.Errorf("vault: init storage: %w", err)
	}

	// Load local state (nodes.json).
	localStatePath := filepath.Join(dataDir, "nodes.json")
	localState, err := LoadLocalState(localStatePath)
	if err != nil {
		return nil, fmt.Errorf("vault: load local state: %w", err)
	}

	// Initialize content resolver with local store.
	// Remote endpoints are added via SetResolverEndpoints().
	resolver := storage.NewContentResolver(store)

	return &Vault{
		Wallet:   w,
		WState:   wState,
		Store:    store,
		Resolver: resolver,
		State:    localState,
		DataDir:  dataDir,
	}, nil
}

// withWriteLock executes fn while holding an exclusive vault lock.
// It reloads state before fn and saves state after fn returns nil error.
func (v *Vault) withWriteLock(fn func() error) error {
	lockPath := filepath.Join(v.DataDir, "vault.lock")
	fl, err := acquireLock(lockPath)
	if err != nil {
		return fmt.Errorf("vault lock: %w", err)
	}
	defer releaseLock(fl)

	// Reload latest state to prevent stale reads.
	if err := v.State.Reload(); err != nil {
		return fmt.Errorf("reload state: %w", err)
	}

	if err := fn(); err != nil {
		return err
	}

	return v.State.Save()
}

// Close releases resources. Vault node state is already persisted by each
// write operation via withWriteLock; Close only saves wallet state (fee
// derivation indexes) to avoid overwriting concurrent node state updates.
func (v *Vault) Close() error {
	if v.SPVStore != nil {
		_ = v.SPVStore.Close()
	}
	return v.saveWalletState()
}

// InitSPV initializes the SPV client and persistent header/tx store.
// Call after Chain is configured. No-op if Chain is nil.
func (v *Vault) InitSPV() error {
	if v.Chain == nil {
		return nil
	}
	dbPath := filepath.Join(v.DataDir, "spv", "spv.db")
	store, err := spv.OpenBoltStore(dbPath)
	if err != nil {
		return fmt.Errorf("vault: open SPV store: %w", err)
	}
	v.SPVStore = store
	v.SPV = network.NewSPVClient(v.Chain, store.Headers())
	return nil
}

// verifyCall holds the in-flight or completed result of a single VerifyTx call.
// Used by verifyOnce (sync.Map) to deduplicate concurrent verifications. [Audit fix M-9]
type verifyCall struct {
	once   sync.Once
	result *network.VerifyResult
	err    error
}

// VerifyTx performs on-demand SPV verification of a transaction.
// If the tx was previously verified and has a cached proof, the result is returned
// immediately without network requests. Otherwise, the proof is fetched from the
// network and backfilled into the local store.
//
// Concurrent calls for the same txid are deduplicated: only one network request
// is made, and all callers receive the same result. [Audit fix M-9]
func (v *Vault) VerifyTx(ctx context.Context, txid string) (*network.VerifyResult, error) {
	if v.SPV == nil {
		return nil, fmt.Errorf("vault: no blockchain service configured (offline mode)")
	}

	// Check local cache for a stored tx with proof.
	if v.SPVStore != nil {
		txidBytes := displayHexToInternal(txid)
		if len(txidBytes) == 32 {
			if stored, err := v.SPVStore.Txs().GetTx(txidBytes); err == nil && stored.Proof != nil {
				return &network.VerifyResult{
					Confirmed:   true,
					BlockHeight: uint64(stored.BlockHeight),
					BlockHash:   hex.EncodeToString(reverseBytesCopy(stored.Proof.BlockHash)),
				}, nil
			}
		}
	}

	// Deduplicate concurrent VerifyTx calls for the same txid. [Audit fix M-9]
	callI, _ := v.verifyOnce.LoadOrStore(txid, &verifyCall{})
	call := callI.(*verifyCall)
	call.once.Do(func() {
		call.result, call.err = v.verifyTxNetwork(ctx, txid)
		// Remove from map so future calls retry (e.g., after transient error).
		v.verifyOnce.Delete(txid)
	})

	return call.result, call.err
}

// verifyTxNetwork performs the actual network verification and backfills the local store.
func (v *Vault) verifyTxNetwork(ctx context.Context, txid string) (*network.VerifyResult, error) {
	result, err := v.SPV.VerifyTx(ctx, txid)
	if err != nil {
		return nil, err
	}

	// Backfill proof into local store if confirmed.
	if result.Confirmed && v.SPVStore != nil {
		txidBytes := displayHexToInternal(txid)
		blockHashBytes := displayHexToInternal(result.BlockHash)
		if len(txidBytes) == 32 {
			proof := &spv.MerkleProof{
				TxID:      txidBytes,
				BlockHash: blockHashBytes,
			}
			stored, getErr := v.SPVStore.Txs().GetTx(txidBytes)
			if getErr == nil {
				// Update existing entry with proof.
				stored.Proof = proof
				stored.BlockHeight = uint32(result.BlockHeight)
				_ = v.SPVStore.Txs().UpdateTx(stored)
			} else {
				// Store new entry.
				newTx := &spv.StoredTx{
					TxID:        txidBytes,
					Proof:       proof,
					BlockHeight: uint32(result.BlockHeight),
				}
				_ = v.SPVStore.Txs().PutTx(newTx)
			}
		}
	}

	return result, nil
}

// reverseBytesCopy returns a reversed copy of a byte slice.
func reverseBytesCopy(b []byte) []byte {
	c := make([]byte, len(b))
	for i, v := range b {
		c[len(b)-1-i] = v
	}
	return c
}

// ResolveVaultIndex resolves a vault name to its account index.
// Empty name uses the first active vault.
func (v *Vault) ResolveVaultIndex(vaultName string) (uint32, error) {
	if vaultName == "" {
		vaults := v.Wallet.ListVaults(v.WState)
		if len(vaults) == 0 {
			return 0, fmt.Errorf("vault: no vaults found; run 'bitfs vault create <name>'")
		}
		return vaults[0].AccountIndex, nil
	}
	vault, err := v.Wallet.GetVault(v.WState, vaultName)
	if err != nil {
		return 0, err
	}
	return vault.AccountIndex, nil
}

// DeriveChangeAddr derives a change address (20-byte pubkey hash) from the fee chain.
// Note: index is incremented eagerly. If the caller's operation fails,
// the index gap is harmless — HD wallets tolerate gaps in derivation.
//
// CONCURRENCY: Must only be called within withWriteLock. The file-level flock
// serializes access, preventing concurrent read-increment races on
// WState.NextChangeIndex. [Audit fix H-2]
func (v *Vault) DeriveChangeAddr() ([]byte, *ec.PrivateKey, error) {
	idx := v.WState.NextChangeIndex
	kp, err := v.Wallet.DeriveFeeKey(wallet.InternalChain, idx)
	if err != nil {
		return nil, nil, fmt.Errorf("vault: derive change key: %w", err)
	}
	v.WState.NextChangeIndex++
	hash := pubKeyHash(kp.PublicKey)
	return hash, kp.PrivateKey, nil
}

// AllocateFeeUTXO finds a fee UTXO with enough funds and returns the tx UTXO
// with the private key attached.
func (v *Vault) AllocateFeeUTXO(minAmount uint64) (*tx.UTXO, error) {
	utxoState := v.State.AllocateFeeUTXO(minAmount)
	if utxoState == nil {
		return nil, fmt.Errorf("vault: no fee UTXO with >= %d sats; run 'bitfs fund' first: %w", minAmount, ErrInsufficientFunds)
	}
	return v.utxoStateToTx(utxoState)
}

// AllocateFeeUTXOWithState finds a fee UTXO with enough funds and returns both
// the tx UTXO (with private key) and the underlying UTXOState for rollback.
// If the transaction build/sign fails, the caller should set utxoState.Spent = false
// to release the UTXO back to the pool.
func (v *Vault) AllocateFeeUTXOWithState(minAmount uint64) (*tx.UTXO, *UTXOState, error) {
	utxoState := v.State.AllocateFeeUTXO(minAmount)
	if utxoState == nil {
		return nil, nil, fmt.Errorf("vault: no fee UTXO with >= %d sats; run 'bitfs fund' first: %w", minAmount, ErrInsufficientFunds)
	}
	txU, err := v.utxoStateToTx(utxoState)
	if err != nil {
		utxoState.Spent = false // rollback on conversion error
		return nil, nil, err
	}
	return txU, utxoState, nil
}

// internalToDisplay converts internal byte order (little-endian) txid bytes
// to display-format hex string (big-endian).
func internalToDisplay(leBytes []byte) string {
	rev := make([]byte, len(leBytes))
	for i, j := 0, len(leBytes)-1; i <= j; i, j = i+1, j-1 {
		rev[i], rev[j] = leBytes[j], leBytes[i]
	}
	return hex.EncodeToString(rev)
}

// utxoStateToTx converts a UTXOState to a tx.UTXO with private key attached.
func (v *Vault) utxoStateToTx(us *UTXOState) (*tx.UTXO, error) {
	// UTXOState.TxID is display format (big-endian hex). Convert to internal
	// (little-endian) for go-sdk chainhash.
	txID := displayHexToInternal(us.TxID)
	if len(txID) != 32 {
		return nil, fmt.Errorf("vault: invalid UTXO txid: %s", us.TxID)
	}
	scriptPK, err := hex.DecodeString(us.ScriptPubKey)
	if err != nil {
		return nil, fmt.Errorf("vault: invalid UTXO script: %w", err)
	}

	// Look up the private key for the UTXO's pubkey.
	privKey, err := v.lookupPrivKey(us.PubKeyHex, us.Type)
	if err != nil {
		return nil, err
	}

	return &tx.UTXO{
		TxID:         txID,
		Vout:         us.Vout,
		Amount:       us.Amount,
		ScriptPubKey: scriptPK,
		PrivateKey:   privKey,
	}, nil
}

// lookupPrivKey finds the private key for a UTXO based on its pubkey and type.
//
// For fee UTXOs, a fast O(1) path uses stored FeeChain/FeeDerivIdx. The linear
// scan fallback exists only for legacy UTXOs created before derivation indices
// were tracked (pre-v0.8). New fee UTXOs always have FeeChain/FeeDerivIdx set
// via TrackNewUTXOs, TrackBatchUTXOs, and RefreshFeeUTXOs.
func (v *Vault) lookupPrivKey(pubKeyHex, utxoType string) (*ec.PrivateKey, error) {
	if utxoType == "fee" {
		// Try direct lookup via stored derivation index first (O(1)).
		us := v.State.FindUTXOByPubKey(pubKeyHex, "fee")
		if us != nil && (us.FeeChain > 0 || us.FeeDerivIdx > 0) {
			kp, err := v.Wallet.DeriveFeeKey(us.FeeChain, us.FeeDerivIdx)
			if err == nil && hex.EncodeToString(kp.PublicKey.Compressed()) == pubKeyHex {
				return kp.PrivateKey, nil
			}
		}

		// Fallback: linear scan for legacy UTXOs without stored derivation indices.
		for i := uint32(0); i < v.WState.NextReceiveIndex+10; i++ {
			kp, err := v.Wallet.DeriveFeeKey(wallet.ExternalChain, i)
			if err != nil {
				continue
			}
			if hex.EncodeToString(kp.PublicKey.Compressed()) == pubKeyHex {
				return kp.PrivateKey, nil
			}
		}
		for i := uint32(0); i < v.WState.NextChangeIndex+10; i++ {
			kp, err := v.Wallet.DeriveFeeKey(wallet.InternalChain, i)
			if err != nil {
				continue
			}
			if hex.EncodeToString(kp.PublicKey.Compressed()) == pubKeyHex {
				return kp.PrivateKey, nil
			}
		}
		return nil, fmt.Errorf("vault: no private key found for fee UTXO pubkey %s", pubKeyHex)
	}

	// Node UTXO — look up the node state for derivation indices.
	node := v.State.GetNode(pubKeyHex)
	if node == nil {
		return nil, fmt.Errorf("vault: unknown node %s", pubKeyHex)
	}
	kp, err := v.Wallet.DeriveNodeKey(node.VaultIndex, node.ChildIndices, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: derive node key: %w", err)
	}
	return kp.PrivateKey, nil
}

// TrackNewUTXOs adds UTXOs produced by a MetanetTx to local state.
func (v *Vault) TrackNewUTXOs(mtx *tx.MetanetTx, nodePubHex, changePubHex string) {
	txIDHex := hex.EncodeToString(mtx.TxID)

	if mtx.NodeUTXO != nil {
		scriptPK, _ := tx.BuildP2PKHScript(mustDecompressPubKey(nodePubHex))
		v.State.AddUTXO(&UTXOState{
			TxID:         txIDHex,
			Vout:         mtx.NodeUTXO.Vout,
			Amount:       mtx.NodeUTXO.Amount,
			ScriptPubKey: hex.EncodeToString(scriptPK),
			PubKeyHex:    nodePubHex,
			Type:         "node",
		})
	}

	// Parent refresh UTXO is tracked by the caller via TrackParentRefreshUTXO.

	if mtx.ChangeUTXO != nil && changePubHex != "" {
		scriptPK, _ := tx.BuildP2PKHScript(mustDecompressPubKey(changePubHex))
		// Change UTXOs are derived from the internal fee chain.
		// DeriveChangeAddr increments NextChangeIndex before returning,
		// so the index used is NextChangeIndex - 1.
		feeDerivIdx := uint32(0)
		if v.WState.NextChangeIndex > 0 {
			feeDerivIdx = v.WState.NextChangeIndex - 1
		}
		v.State.AddUTXO(&UTXOState{
			TxID:         txIDHex,
			Vout:         mtx.ChangeUTXO.Vout,
			Amount:       mtx.ChangeUTXO.Amount,
			ScriptPubKey: hex.EncodeToString(scriptPK),
			PubKeyHex:    changePubHex,
			Type:         "fee",
			FeeChain:     wallet.InternalChain,
			FeeDerivIdx:  feeDerivIdx,
		})
	}
}

// TrackParentRefreshUTXO adds the parent refresh UTXO to local state.
func (v *Vault) TrackParentRefreshUTXO(mtx *tx.MetanetTx, parentPubHex string) {
	if mtx.ParentUTXO == nil {
		return
	}
	txIDHex := hex.EncodeToString(mtx.TxID)
	scriptPK, _ := tx.BuildP2PKHScript(mustDecompressPubKey(parentPubHex))
	v.State.AddUTXO(&UTXOState{
		TxID:         txIDHex,
		Vout:         mtx.ParentUTXO.Vout,
		Amount:       mtx.ParentUTXO.Amount,
		ScriptPubKey: hex.EncodeToString(scriptPK),
		PubKeyHex:    parentPubHex,
		Type:         "node",
	})
}

// TrackBatchUTXOs registers all UTXOs produced by a BatchResult into local state.
// opPubKeys maps op index -> pubkey hex for the node that op creates/updates.
// changePubHex is the change address owner.
func (v *Vault) TrackBatchUTXOs(result *tx.BatchResult, opPubKeys []string, changePubHex string) {
	txIDHex := internalToDisplay(result.TxID)

	for i, opResult := range result.NodeOps {
		if opResult.NodeUTXO == nil {
			continue // OpDelete — no UTXO produced
		}
		if i >= len(opPubKeys) || opPubKeys[i] == "" {
			continue
		}
		scriptPK, _ := tx.BuildP2PKHScript(mustDecompressPubKey(opPubKeys[i]))
		v.State.AddUTXO(&UTXOState{
			TxID:         txIDHex,
			Vout:         opResult.NodeUTXO.Vout,
			Amount:       opResult.NodeUTXO.Amount,
			ScriptPubKey: hex.EncodeToString(scriptPK),
			PubKeyHex:    opPubKeys[i],
			Type:         "node",
		})
	}

	if result.ChangeUTXO != nil && changePubHex != "" {
		scriptPK, _ := tx.BuildP2PKHScript(mustDecompressPubKey(changePubHex))
		feeDerivIdx := uint32(0)
		if v.WState.NextChangeIndex > 0 {
			feeDerivIdx = v.WState.NextChangeIndex - 1
		}
		v.State.AddUTXO(&UTXOState{
			TxID:         txIDHex,
			Vout:         result.ChangeUTXO.Vout,
			Amount:       result.ChangeUTXO.Amount,
			ScriptPubKey: hex.EncodeToString(scriptPK),
			PubKeyHex:    changePubHex,
			Type:         "fee",
			FeeChain:     wallet.InternalChain,
			FeeDerivIdx:  feeDerivIdx,
		})
	}
}

// IsOnline returns true if a blockchain service is configured.
func (v *Vault) IsOnline() bool {
	return v.Chain != nil
}

// broadcastIfOnline broadcasts the signed transaction if a blockchain service
// is configured. Returns nil silently when offline (no Chain).
func (v *Vault) broadcastIfOnline(txHex string) error {
	if v.Chain == nil {
		return nil
	}
	_, err := v.BroadcastTx(context.Background(), txHex)
	return err
}

// BroadcastTx submits a signed transaction to the network.
// If SPV storage is available, the tx is stored (without proof) for later verification.
func (v *Vault) BroadcastTx(ctx context.Context, rawTxHex string) (string, error) {
	if v.Chain == nil {
		return "", fmt.Errorf("vault: no blockchain service configured (offline mode)")
	}
	txid, err := v.Chain.BroadcastTx(ctx, rawTxHex)
	if err != nil {
		return "", err
	}

	// Store tx for later proof backfill (best-effort, don't fail on store error).
	if v.SPVStore != nil {
		rawTx, decErr := hex.DecodeString(rawTxHex)
		if decErr == nil {
			txidBytes := displayHexToInternal(txid)
			if len(txidBytes) == 32 {
				storedTx := &spv.StoredTx{
					TxID:  txidBytes,
					RawTx: rawTx,
				}
				// Ignore duplicate errors (tx may already be stored).
				_ = v.SPVStore.Txs().PutTx(storedTx)
			}
		}
	}

	return txid, nil
}

// displayHexToInternal converts a display hex string (big-endian) to internal
// byte order (little-endian, as used by DoubleHash output).
func displayHexToInternal(displayHex string) []byte {
	b, err := hex.DecodeString(displayHex)
	if err != nil {
		return nil
	}
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

// RefreshFeeUTXOs queries the network for unspent outputs at the given address
// and adds any new ones to local state as fee UTXOs.
// chain and derivIdx identify the HD derivation path for key lookup.
func (v *Vault) RefreshFeeUTXOs(ctx context.Context, address, pubKeyHex string, chain, derivIdx uint32) error {
	if v.Chain == nil {
		return fmt.Errorf("vault: no blockchain service configured")
	}

	// Import the address into the node's wallet so listunspent can discover its UTXOs.
	// This is a no-op if the address is already imported.
	if err := v.Chain.ImportAddress(ctx, address); err != nil {
		return fmt.Errorf("vault: import address: %w", err)
	}

	utxos, err := v.Chain.ListUnspent(ctx, address)
	if err != nil {
		return fmt.Errorf("vault: list unspent: %w", err)
	}

	for _, u := range utxos {
		// Use the mutex-guarded ContainsUTXO method instead of reading
		// v.State.UTXOs directly without lock. [Audit fix M-6]
		if !v.State.ContainsUTXO(u.TxID, u.Vout) {
			v.State.AddUTXO(&UTXOState{
				TxID:         u.TxID,
				Vout:         u.Vout,
				Amount:       u.Amount,
				ScriptPubKey: u.ScriptPubKey,
				PubKeyHex:    pubKeyHex,
				Type:         "fee",
				FeeChain:     chain,
				FeeDerivIdx:  derivIdx,
			})
		}
	}

	return nil
}
