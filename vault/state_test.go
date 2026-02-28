package vault

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLocalState(t *testing.T) {
	s := NewLocalState("/tmp/test.json")
	if s.Nodes == nil {
		t.Fatal("Nodes map should not be nil")
	}
	if s.UTXOs == nil {
		t.Fatal("UTXOs slice should not be nil")
	}
	if s.RootTxID == nil {
		t.Fatal("RootTxID map should not be nil")
	}
}

func TestLoadLocalState_FileNotExist(t *testing.T) {
	s, err := LoadLocalState(filepath.Join(t.TempDir(), "nonexistent.json"))
	if err != nil {
		t.Fatalf("LoadLocalState on missing file: %v", err)
	}
	if s.Nodes == nil || s.UTXOs == nil || s.RootTxID == nil {
		t.Error("maps/slices should be initialized on missing file")
	}
}

func TestLoadLocalState_InvalidJSON(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(p, []byte("not json"), 0600)

	_, err := LoadLocalState(p)
	if err == nil {
		t.Error("LoadLocalState(invalid JSON) expected error")
	}
}

func TestLocalState_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")

	s := NewLocalState(p)
	s.SetNode("aabb", &NodeState{
		PubKeyHex: "aabb",
		Type:      "file",
		Path:      "/hello.txt",
	})
	s.AddUTXO(&UTXOState{
		TxID:   "cc11",
		Amount: 5000,
		Type:   "fee",
	})
	s.mu.Lock()
	s.RootTxID[0] = "dd22"
	s.mu.Unlock()

	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := LoadLocalState(p)
	if err != nil {
		t.Fatalf("LoadLocalState: %v", err)
	}

	if loaded.GetNode("aabb") == nil {
		t.Error("loaded state missing node 'aabb'")
	}
	if loaded.GetNode("aabb").Path != "/hello.txt" {
		t.Errorf("node path = %q, want /hello.txt", loaded.GetNode("aabb").Path)
	}
	if len(loaded.UTXOs) != 1 || loaded.UTXOs[0].Amount != 5000 {
		t.Errorf("loaded UTXOs = %v, want 1 UTXO with 5000 sats", loaded.UTXOs)
	}
	if loaded.RootTxID[0] != "dd22" {
		t.Errorf("RootTxID[0] = %q, want dd22", loaded.RootTxID[0])
	}
}

func TestLocalState_SaveCreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "deep", "state.json")

	s := NewLocalState(p)
	if err := s.Save(); err != nil {
		t.Fatalf("Save with nested dir: %v", err)
	}

	if _, err := os.Stat(p); err != nil {
		t.Errorf("file not created: %v", err)
	}
}

func TestLoadLocalState_NilMaps(t *testing.T) {
	// JSON with null/missing maps should be initialized.
	p := filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(p, []byte(`{}`), 0600)

	s, err := LoadLocalState(p)
	if err != nil {
		t.Fatalf("LoadLocalState: %v", err)
	}
	if s.Nodes == nil {
		t.Error("Nodes should be initialized")
	}
	if s.UTXOs == nil {
		t.Error("UTXOs should be initialized")
	}
	if s.RootTxID == nil {
		t.Error("RootTxID should be initialized")
	}
}

func TestLocalState_AllocateFeeUTXO(t *testing.T) {
	s := NewLocalState("")

	// No UTXOs yet.
	if u := s.AllocateFeeUTXO(1000); u != nil {
		t.Error("expected nil when no UTXOs")
	}

	// Add some UTXOs.
	s.AddUTXO(&UTXOState{TxID: "a1", Amount: 500, Type: "fee"})
	s.AddUTXO(&UTXOState{TxID: "a2", Amount: 2000, Type: "fee"})
	s.AddUTXO(&UTXOState{TxID: "a3", Amount: 1000, Type: "node"}) // not a fee UTXO
	s.AddUTXO(&UTXOState{TxID: "a4", Amount: 3000, Type: "fee"})

	// Allocate >= 1500 sats.
	u := s.AllocateFeeUTXO(1500)
	if u == nil {
		t.Fatal("expected UTXO")
	}
	if u.TxID != "a2" {
		t.Errorf("got TxID=%s, want a2", u.TxID)
	}
	if !u.Spent {
		t.Error("allocated UTXO should be marked spent")
	}

	// Try to allocate again >= 1500 — a2 is spent, should get a4.
	u = s.AllocateFeeUTXO(1500)
	if u == nil {
		t.Fatal("expected UTXO")
	}
	if u.TxID != "a4" {
		t.Errorf("got TxID=%s, want a4", u.TxID)
	}

	// No more fee UTXOs with >= 1500.
	if u := s.AllocateFeeUTXO(1500); u != nil {
		t.Error("expected nil, all large UTXOs spent")
	}

	// But small one is still available.
	u = s.AllocateFeeUTXO(100)
	if u == nil || u.TxID != "a1" {
		t.Error("expected a1 for small allocation")
	}
}

func TestLocalState_GetNodeUTXO(t *testing.T) {
	s := NewLocalState("")

	// No UTXOs.
	if u := s.GetNodeUTXO("pub1"); u != nil {
		t.Error("expected nil for empty state")
	}

	s.AddUTXO(&UTXOState{TxID: "tx1", PubKeyHex: "pub1", Type: "node", Amount: 546})
	s.AddUTXO(&UTXOState{TxID: "tx2", PubKeyHex: "pub2", Type: "node", Amount: 546})
	s.AddUTXO(&UTXOState{TxID: "tx3", PubKeyHex: "pub1", Type: "fee", Amount: 1000}) // wrong type

	u := s.GetNodeUTXO("pub1")
	if u == nil {
		t.Fatal("expected UTXO for pub1")
	}
	if u.TxID != "tx1" {
		t.Errorf("got TxID=%s, want tx1", u.TxID)
	}

	// Wrong pubkey.
	if u := s.GetNodeUTXO("pub3"); u != nil {
		t.Error("expected nil for unknown pubkey")
	}
}

func TestLocalState_GetSetNode(t *testing.T) {
	s := NewLocalState("")

	// Empty state.
	if n := s.GetNode("abc"); n != nil {
		t.Error("expected nil for empty state")
	}

	node := &NodeState{PubKeyHex: "abc", Type: "dir", Path: "/docs"}
	s.SetNode("abc", node)

	got := s.GetNode("abc")
	if got == nil {
		t.Fatal("expected node")
	}
	if got.Path != "/docs" {
		t.Errorf("node.Path = %q, want /docs", got.Path)
	}

	// Overwrite.
	s.SetNode("abc", &NodeState{PubKeyHex: "abc", Path: "/new"})
	if s.GetNode("abc").Path != "/new" {
		t.Error("overwrite failed")
	}
}

func TestLocalState_FindNodeByPath(t *testing.T) {
	s := NewLocalState("")
	s.SetNode("a", &NodeState{PubKeyHex: "a", Path: "/alpha"})
	s.SetNode("b", &NodeState{PubKeyHex: "b", Path: "/beta"})

	// Found.
	n := s.FindNodeByPath("/alpha")
	if n == nil || n.PubKeyHex != "a" {
		t.Error("expected node 'a' at /alpha")
	}

	// Not found.
	if s.FindNodeByPath("/gamma") != nil {
		t.Error("expected nil for missing path")
	}
}

func TestReleaseUTXO_MarksUnspent(t *testing.T) {
	s := NewLocalState("")
	s.AddUTXO(&UTXOState{TxID: "aa11", Vout: 0, Amount: 5000, Type: "fee"})

	// Allocate it — should be marked spent.
	u := s.AllocateFeeUTXO(1000)
	require.NotNil(t, u)
	assert.True(t, u.Spent, "UTXO should be spent after allocation")

	// Release it — should be marked unspent again.
	s.ReleaseUTXO("aa11", 0)
	assert.False(t, u.Spent, "UTXO should be unspent after release")

	// Verify it can be re-allocated.
	u2 := s.AllocateFeeUTXO(1000)
	require.NotNil(t, u2)
	assert.Equal(t, "aa11", u2.TxID)
}

func TestReleaseUTXO_NonExistent(t *testing.T) {
	s := NewLocalState("")
	s.AddUTXO(&UTXOState{TxID: "bb22", Vout: 0, Amount: 3000, Type: "fee", Spent: true})

	// Release a UTXO that does not exist — no panic, no state change.
	s.ReleaseUTXO("nonexistent", 0)
	s.ReleaseUTXO("bb22", 99) // same txid, wrong vout

	// Original UTXO should still be spent.
	s.mu.Lock()
	assert.True(t, s.UTXOs[0].Spent, "unrelated UTXO should remain spent")
	s.mu.Unlock()
}

func TestReleaseUTXO_MatchesTxIDAndVout(t *testing.T) {
	s := NewLocalState("")
	s.AddUTXO(&UTXOState{TxID: "cc33", Vout: 0, Amount: 1000, Type: "fee", Spent: true})
	s.AddUTXO(&UTXOState{TxID: "cc33", Vout: 1, Amount: 2000, Type: "fee", Spent: true})

	// Release only vout=1.
	s.ReleaseUTXO("cc33", 1)

	s.mu.Lock()
	assert.True(t, s.UTXOs[0].Spent, "vout=0 should still be spent")
	assert.False(t, s.UTXOs[1].Spent, "vout=1 should be unspent after release")
	s.mu.Unlock()
}
