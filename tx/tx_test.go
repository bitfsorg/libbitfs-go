package tx

import (
	"bytes"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKeyPair(t *testing.T) (*ec.PrivateKey, *ec.PublicKey) {
	t.Helper()
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	return privKey, privKey.PubKey()
}

func testFeeUTXO(t *testing.T, amount uint64) *UTXO {
	t.Helper()
	return &UTXO{
		TxID:   bytes.Repeat([]byte{0x01}, 32),
		Vout:   0,
		Amount: amount,
	}
}

// --- OP_RETURN tests ---

func TestBuildOPReturnData(t *testing.T) {
	_, pubKey := generateTestKeyPair(t)
	parentTxID := bytes.Repeat([]byte{0xab}, 32)
	payload := []byte("test protobuf payload")

	pushes, err := BuildOPReturnData(pubKey, parentTxID, payload)
	require.NoError(t, err)
	assert.Len(t, pushes, 4)

	// Verify MetaFlag
	assert.Equal(t, MetaFlagBytes, pushes[0])

	// Verify P_node
	assert.Len(t, pushes[1], CompressedPubKeyLen)

	// Verify TxID_parent
	assert.Equal(t, parentTxID, pushes[2])

	// Verify payload
	assert.Equal(t, payload, pushes[3])
}

func TestBuildOPReturnData_RootNode(t *testing.T) {
	_, pubKey := generateTestKeyPair(t)
	payload := []byte("root node payload")

	// Root node has empty parent TxID
	pushes, err := BuildOPReturnData(pubKey, nil, payload)
	require.NoError(t, err)
	assert.Len(t, pushes, 4)
	assert.Empty(t, pushes[2], "root node should have empty parent TxID")
}

func TestBuildOPReturnData_NilPubKey(t *testing.T) {
	payload := []byte("test")
	_, err := BuildOPReturnData(nil, nil, payload)
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestBuildOPReturnData_EmptyPayload(t *testing.T) {
	_, pubKey := generateTestKeyPair(t)
	_, err := BuildOPReturnData(pubKey, nil, []byte{})
	assert.ErrorIs(t, err, ErrInvalidPayload)
}

func TestBuildOPReturnData_InvalidParentTxID(t *testing.T) {
	_, pubKey := generateTestKeyPair(t)
	payload := []byte("test")

	_, err := BuildOPReturnData(pubKey, []byte{0x01, 0x02}, payload) // not 32 bytes
	assert.ErrorIs(t, err, ErrInvalidParentTxID)
}

func TestParseOPReturnData(t *testing.T) {
	_, pubKey := generateTestKeyPair(t)
	parentTxID := bytes.Repeat([]byte{0xab}, 32)
	payload := []byte("test payload data")

	pushes, err := BuildOPReturnData(pubKey, parentTxID, payload)
	require.NoError(t, err)

	pNode, parsedParent, parsedPayload, err := ParseOPReturnData(pushes)
	require.NoError(t, err)
	assert.Equal(t, pubKey.Compressed(), pNode)
	assert.Equal(t, parentTxID, parsedParent)
	assert.Equal(t, payload, parsedPayload)
}

func TestParseOPReturnData_RootNode(t *testing.T) {
	_, pubKey := generateTestKeyPair(t)
	payload := []byte("root payload")

	pushes, err := BuildOPReturnData(pubKey, nil, payload)
	require.NoError(t, err)

	_, parsedParent, _, err := ParseOPReturnData(pushes)
	require.NoError(t, err)
	assert.Empty(t, parsedParent)
}

func TestParseOPReturnData_TooFewPushes(t *testing.T) {
	_, _, _, err := ParseOPReturnData([][]byte{{0x01}})
	assert.ErrorIs(t, err, ErrInvalidOPReturn)
}

func TestParseOPReturnData_WrongMetaFlag(t *testing.T) {
	pushes := [][]byte{
		{0xff, 0xff, 0xff, 0xff}, // wrong flag
		bytes.Repeat([]byte{0x02}, 33),
		bytes.Repeat([]byte{0x03}, 32),
		[]byte("payload"),
	}
	_, _, _, err := ParseOPReturnData(pushes)
	assert.ErrorIs(t, err, ErrNotMetanetTx)
}

func TestParseOPReturnData_InvalidPNodeLength(t *testing.T) {
	pushes := [][]byte{
		MetaFlagBytes,
		{0x02, 0x03}, // too short
		bytes.Repeat([]byte{0x03}, 32),
		[]byte("payload"),
	}
	_, _, _, err := ParseOPReturnData(pushes)
	assert.ErrorIs(t, err, ErrInvalidOPReturn)
}

// --- BuildOPReturnData/ParseOPReturnData round-trip ---

func TestOPReturn_RoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		parentTxID []byte
		payload    []byte
	}{
		{"root node", nil, []byte("root payload")},
		{"child node", bytes.Repeat([]byte{0xab}, 32), []byte("child payload")},
		{"large payload", bytes.Repeat([]byte{0xcd}, 32), bytes.Repeat([]byte("x"), 10000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, pubKey := generateTestKeyPair(t)

			pushes, err := BuildOPReturnData(pubKey, tt.parentTxID, tt.payload)
			require.NoError(t, err)

			pNode, parentTxID, payload, err := ParseOPReturnData(pushes)
			require.NoError(t, err)

			assert.Equal(t, pubKey.Compressed(), pNode)
			assert.Equal(t, tt.parentTxID, parentTxID)
			assert.Equal(t, tt.payload, payload)
		})
	}
}

// --- Fee estimation tests ---

func TestEstimateFee(t *testing.T) {
	tests := []struct {
		name   string
		size   int
		rate   uint64
		minFee uint64
	}{
		{"minimal tx", 200, 1, 1},
		{"1KB tx at 1 sat/KB", 1000, 1, 1},
		{"2KB tx at 1 sat/KB", 2000, 1, 2},
		{"500B tx at 2 sat/KB", 500, 2, 1},
		{"default rate", 1000, 0, 1}, // 0 rate uses default
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fee := EstimateFee(tt.size, tt.rate)
			assert.GreaterOrEqual(t, fee, tt.minFee)
		})
	}
}

func TestEstimateTxSize(t *testing.T) {
	size := EstimateTxSize(1, 3, 100)
	assert.Greater(t, size, 0)

	// More inputs/outputs = larger
	size2 := EstimateTxSize(2, 4, 100)
	assert.Greater(t, size2, size)

	// Larger payload = larger
	size3 := EstimateTxSize(1, 3, 1000)
	assert.Greater(t, size3, size)
}

// --- BuildCreateRoot tests ---

func TestBuildCreateRoot(t *testing.T) {
	_, nodePub := generateTestKeyPair(t)
	payload := []byte("root node protobuf payload data")

	result, err := BuildCreateRoot(&CreateRootParams{
		NodePubKey: nodePub,
		Payload:    payload,
		FeeUTXO:    testFeeUTXO(t, 100000),
		FeeRate:    1,
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.NodeUTXO)
	assert.Equal(t, uint32(1), result.NodeUTXO.Vout)
	assert.Equal(t, DustLimit, result.NodeUTXO.Amount)
	assert.Nil(t, result.ParentUTXO, "root has no parent refresh")
}

func TestBuildCreateRoot_InsufficientFunds(t *testing.T) {
	_, nodePub := generateTestKeyPair(t)
	payload := []byte("root node payload")

	_, err := BuildCreateRoot(&CreateRootParams{
		NodePubKey: nodePub,
		Payload:    payload,
		FeeUTXO:    testFeeUTXO(t, 100), // too little
		FeeRate:    1,
	})
	assert.ErrorIs(t, err, ErrInsufficientFunds)
}

func TestBuildCreateRoot_NilParams(t *testing.T) {
	_, err := BuildCreateRoot(nil)
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestBuildCreateRoot_NilPubKey(t *testing.T) {
	_, err := BuildCreateRoot(&CreateRootParams{
		NodePubKey: nil,
		Payload:    []byte("test"),
		FeeUTXO:    testFeeUTXO(t, 100000),
	})
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestBuildCreateRoot_EmptyPayload(t *testing.T) {
	_, nodePub := generateTestKeyPair(t)
	_, err := BuildCreateRoot(&CreateRootParams{
		NodePubKey: nodePub,
		Payload:    []byte{},
		FeeUTXO:    testFeeUTXO(t, 100000),
	})
	assert.ErrorIs(t, err, ErrInvalidPayload)
}

// --- BuildCreateChild tests ---

func TestBuildCreateChild(t *testing.T) {
	_, nodePub := generateTestKeyPair(t)
	parentPriv, parentPub := generateTestKeyPair(t)
	parentTxID := bytes.Repeat([]byte{0xaa}, 32)
	payload := []byte("child node protobuf payload")

	result, err := BuildCreateChild(&CreateChildParams{
		NodePubKey:    nodePub,
		ParentTxID:    parentTxID,
		Payload:       payload,
		ParentUTXO:    &UTXO{TxID: parentTxID, Vout: 1, Amount: DustLimit, PrivateKey: parentPriv},
		ParentPrivKey: parentPriv,
		FeeUTXO:       testFeeUTXO(t, 100000),
		ParentPubKey:  parentPub,
		FeeRate:       1,
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.NodeUTXO)
	assert.Equal(t, uint32(1), result.NodeUTXO.Vout)
	assert.NotNil(t, result.ParentUTXO, "child should have parent refresh")
	assert.Equal(t, uint32(2), result.ParentUTXO.Vout)
	assert.Equal(t, DustLimit, result.ParentUTXO.Amount)
}

func TestBuildCreateChild_InvalidParentTxID(t *testing.T) {
	_, nodePub := generateTestKeyPair(t)
	_, parentPub := generateTestKeyPair(t)

	_, err := BuildCreateChild(&CreateChildParams{
		NodePubKey:   nodePub,
		ParentTxID:   []byte{0x01}, // wrong length
		Payload:      []byte("test"),
		ParentUTXO:   &UTXO{Amount: DustLimit},
		FeeUTXO:      testFeeUTXO(t, 100000),
		ParentPubKey: parentPub,
	})
	assert.ErrorIs(t, err, ErrInvalidParentTxID)
}

// --- BuildSelfUpdate tests ---

func TestBuildSelfUpdate(t *testing.T) {
	nodePriv, nodePub := generateTestKeyPair(t)
	parentTxID := bytes.Repeat([]byte{0xbb}, 32)
	payload := []byte("updated protobuf payload")

	result, err := BuildSelfUpdate(&SelfUpdateParams{
		NodePubKey:  nodePub,
		NodePrivKey: nodePriv,
		ParentTxID:  parentTxID,
		Payload:     payload,
		NodeUTXO:    &UTXO{Amount: DustLimit, PrivateKey: nodePriv},
		FeeUTXO:     testFeeUTXO(t, 100000),
		FeeRate:     1,
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.NodeUTXO)
	assert.Equal(t, uint32(1), result.NodeUTXO.Vout)
	assert.Nil(t, result.ParentUTXO, "self-update has no parent refresh")
}

func TestBuildSelfUpdate_EmptyParentTxID(t *testing.T) {
	// Root node self-update may have empty parent TxID
	nodePriv, nodePub := generateTestKeyPair(t)
	payload := []byte("root update payload")

	result, err := BuildSelfUpdate(&SelfUpdateParams{
		NodePubKey:  nodePub,
		NodePrivKey: nodePriv,
		ParentTxID:  nil, // root has no parent
		Payload:     payload,
		NodeUTXO:    &UTXO{Amount: DustLimit, PrivateKey: nodePriv},
		FeeUTXO:     testFeeUTXO(t, 100000),
		FeeRate:     1,
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// --- BuildDataTransaction tests ---

func TestBuildDataTransaction(t *testing.T) {
	_, nodePub := generateTestKeyPair(t)
	content := bytes.Repeat([]byte("encrypted chunk data"), 100)

	result, err := BuildDataTransaction(&DataTxParams{
		NodePubKey: nodePub,
		Content:    content,
		SourceUTXO: testFeeUTXO(t, 100000),
		FeeRate:    1,
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.NodeUTXO)
}

func TestBuildDataTransaction_EmptyContent(t *testing.T) {
	_, nodePub := generateTestKeyPair(t)

	_, err := BuildDataTransaction(&DataTxParams{
		NodePubKey: nodePub,
		Content:    []byte{},
		SourceUTXO: testFeeUTXO(t, 100000),
	})
	assert.ErrorIs(t, err, ErrInvalidPayload)
}

func TestBuildDataTransaction_InsufficientFunds(t *testing.T) {
	_, nodePub := generateTestKeyPair(t)
	content := bytes.Repeat([]byte("data"), 10000) // large content

	_, err := BuildDataTransaction(&DataTxParams{
		NodePubKey: nodePub,
		Content:    content,
		SourceUTXO: testFeeUTXO(t, 100), // too little
		FeeRate:    1,
	})
	assert.ErrorIs(t, err, ErrInsufficientFunds)
}

// --- Constants tests ---

func TestConstants(t *testing.T) {
	assert.Equal(t, []byte{0x6d, 0x65, 0x74, 0x61}, MetaFlagBytes)
	assert.Equal(t, "meta", MetaFlag)
	assert.Equal(t, uint64(546), DustLimit)
	assert.Equal(t, 33, CompressedPubKeyLen)
	assert.Equal(t, 32, TxIDLen)
}

// ===========================================================================
// Supplementary tests -- added to close AUDIT.md gaps
// ===========================================================================

// --- Gap 1: BuildCreateChild nil parameter validation (5 sub-tests) ---

func TestBuildCreateChild_NilParams(t *testing.T) {
	_, nodePub := generateTestKeyPair(t)
	_, parentPub := generateTestKeyPair(t)
	parentTxID := bytes.Repeat([]byte{0xaa}, 32)

	tests := []struct {
		name   string
		params *CreateChildParams
	}{
		{
			"nil params",
			nil,
		},
		{
			"nil NodePubKey",
			&CreateChildParams{
				NodePubKey:   nil,
				ParentTxID:   parentTxID,
				Payload:      []byte("test"),
				ParentUTXO:   &UTXO{TxID: parentTxID, Vout: 1, Amount: DustLimit},
				FeeUTXO:      testFeeUTXO(t, 100000),
				ParentPubKey: parentPub,
			},
		},
		{
			"nil ParentPubKey",
			&CreateChildParams{
				NodePubKey:   nodePub,
				ParentTxID:   parentTxID,
				Payload:      []byte("test"),
				ParentUTXO:   &UTXO{TxID: parentTxID, Vout: 1, Amount: DustLimit},
				FeeUTXO:      testFeeUTXO(t, 100000),
				ParentPubKey: nil,
			},
		},
		{
			"nil ParentUTXO",
			&CreateChildParams{
				NodePubKey:   nodePub,
				ParentTxID:   parentTxID,
				Payload:      []byte("test"),
				ParentUTXO:   nil,
				FeeUTXO:      testFeeUTXO(t, 100000),
				ParentPubKey: parentPub,
			},
		},
		{
			"nil FeeUTXO",
			&CreateChildParams{
				NodePubKey:   nodePub,
				ParentTxID:   parentTxID,
				Payload:      []byte("test"),
				ParentUTXO:   &UTXO{TxID: parentTxID, Vout: 1, Amount: DustLimit},
				FeeUTXO:      nil,
				ParentPubKey: parentPub,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildCreateChild(tt.params)
			assert.ErrorIs(t, err, ErrNilParam)
		})
	}
}

// --- Gap 2: BuildCreateChild insufficient funds ---

func TestBuildCreateChild_InsufficientFunds(t *testing.T) {
	_, nodePub := generateTestKeyPair(t)
	parentPriv, parentPub := generateTestKeyPair(t)
	parentTxID := bytes.Repeat([]byte{0xaa}, 32)

	_, err := BuildCreateChild(&CreateChildParams{
		NodePubKey:    nodePub,
		ParentTxID:    parentTxID,
		Payload:       []byte("child payload"),
		ParentUTXO:    &UTXO{TxID: parentTxID, Vout: 1, Amount: DustLimit, PrivateKey: parentPriv},
		ParentPrivKey: parentPriv,
		FeeUTXO:       testFeeUTXO(t, 100), // too little -- combined with DustLimit still not enough
		ParentPubKey:  parentPub,
		FeeRate:       1,
	})
	assert.ErrorIs(t, err, ErrInsufficientFunds)
}

// --- Gap 3: BuildCreateChild empty payload ---

func TestBuildCreateChild_EmptyPayload(t *testing.T) {
	_, nodePub := generateTestKeyPair(t)
	parentPriv, parentPub := generateTestKeyPair(t)
	parentTxID := bytes.Repeat([]byte{0xaa}, 32)

	_, err := BuildCreateChild(&CreateChildParams{
		NodePubKey:    nodePub,
		ParentTxID:    parentTxID,
		Payload:       []byte{}, // empty
		ParentUTXO:    &UTXO{TxID: parentTxID, Vout: 1, Amount: DustLimit, PrivateKey: parentPriv},
		ParentPrivKey: parentPriv,
		FeeUTXO:       testFeeUTXO(t, 100000),
		ParentPubKey:  parentPub,
		FeeRate:       1,
	})
	assert.ErrorIs(t, err, ErrInvalidPayload)
}

// --- Gap 4: BuildSelfUpdate nil parameter validation (4 sub-tests) ---

func TestBuildSelfUpdate_NilParams(t *testing.T) {
	nodePriv, nodePub := generateTestKeyPair(t)
	parentTxID := bytes.Repeat([]byte{0xbb}, 32)

	tests := []struct {
		name   string
		params *SelfUpdateParams
	}{
		{
			"nil params",
			nil,
		},
		{
			"nil NodePubKey",
			&SelfUpdateParams{
				NodePubKey:  nil,
				NodePrivKey: nodePriv,
				ParentTxID:  parentTxID,
				Payload:     []byte("test"),
				NodeUTXO:    &UTXO{Amount: DustLimit, PrivateKey: nodePriv},
				FeeUTXO:     testFeeUTXO(t, 100000),
			},
		},
		{
			"nil NodeUTXO",
			&SelfUpdateParams{
				NodePubKey:  nodePub,
				NodePrivKey: nodePriv,
				ParentTxID:  parentTxID,
				Payload:     []byte("test"),
				NodeUTXO:    nil,
				FeeUTXO:     testFeeUTXO(t, 100000),
			},
		},
		{
			"nil FeeUTXO",
			&SelfUpdateParams{
				NodePubKey:  nodePub,
				NodePrivKey: nodePriv,
				ParentTxID:  parentTxID,
				Payload:     []byte("test"),
				NodeUTXO:    &UTXO{Amount: DustLimit, PrivateKey: nodePriv},
				FeeUTXO:     nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildSelfUpdate(tt.params)
			assert.ErrorIs(t, err, ErrNilParam)
		})
	}
}

// --- Gap 5: BuildSelfUpdate insufficient funds ---

func TestBuildSelfUpdate_InsufficientFunds(t *testing.T) {
	nodePriv, nodePub := generateTestKeyPair(t)
	parentTxID := bytes.Repeat([]byte{0xbb}, 32)

	// NodeUTXO.Amount=1 + FeeUTXO.Amount=1 = 2 sat total, far below DustLimit+fee (~547+)
	_, err := BuildSelfUpdate(&SelfUpdateParams{
		NodePubKey:  nodePub,
		NodePrivKey: nodePriv,
		ParentTxID:  parentTxID,
		Payload:     []byte("update payload"),
		NodeUTXO:    &UTXO{Amount: 1, PrivateKey: nodePriv},
		FeeUTXO:     testFeeUTXO(t, 1), // too little
		FeeRate:     1,
	})
	assert.ErrorIs(t, err, ErrInsufficientFunds)
}

// --- Gap 6: BuildSelfUpdate invalid parent TxID (non-empty, non-32-byte) ---

func TestBuildSelfUpdate_InvalidParentTxID(t *testing.T) {
	nodePriv, nodePub := generateTestKeyPair(t)

	_, err := BuildSelfUpdate(&SelfUpdateParams{
		NodePubKey:  nodePub,
		NodePrivKey: nodePriv,
		ParentTxID:  []byte{0x01, 0x02}, // not 0 and not 32 bytes
		Payload:     []byte("update payload"),
		NodeUTXO:    &UTXO{Amount: DustLimit, PrivateKey: nodePriv},
		FeeUTXO:     testFeeUTXO(t, 100000),
		FeeRate:     1,
	})
	assert.ErrorIs(t, err, ErrInvalidParentTxID)
}

// --- Gap 7: BuildSelfUpdate empty payload ---

func TestBuildSelfUpdate_EmptyPayload(t *testing.T) {
	nodePriv, nodePub := generateTestKeyPair(t)
	parentTxID := bytes.Repeat([]byte{0xbb}, 32)

	_, err := BuildSelfUpdate(&SelfUpdateParams{
		NodePubKey:  nodePub,
		NodePrivKey: nodePriv,
		ParentTxID:  parentTxID,
		Payload:     []byte{}, // empty
		NodeUTXO:    &UTXO{Amount: DustLimit, PrivateKey: nodePriv},
		FeeUTXO:     testFeeUTXO(t, 100000),
		FeeRate:     1,
	})
	assert.ErrorIs(t, err, ErrInvalidPayload)
}

// --- Gap 8: BuildDataTransaction nil parameter validation (3 sub-tests) ---

func TestBuildDataTransaction_NilParams(t *testing.T) {
	_, nodePub := generateTestKeyPair(t)

	tests := []struct {
		name   string
		params *DataTxParams
	}{
		{
			"nil params",
			nil,
		},
		{
			"nil NodePubKey",
			&DataTxParams{
				NodePubKey: nil,
				Content:    []byte("some content"),
				SourceUTXO: testFeeUTXO(t, 100000),
			},
		},
		{
			"nil SourceUTXO",
			&DataTxParams{
				NodePubKey: nodePub,
				Content:    []byte("some content"),
				SourceUTXO: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildDataTransaction(tt.params)
			assert.ErrorIs(t, err, ErrNilParam)
		})
	}
}

// --- Gap 9: BuildCreateRoot nil FeeUTXO ---

func TestBuildCreateRoot_NilFeeUTXO(t *testing.T) {
	_, nodePub := generateTestKeyPair(t)

	_, err := BuildCreateRoot(&CreateRootParams{
		NodePubKey: nodePub,
		Payload:    []byte("test"),
		FeeUTXO:    nil,
	})
	assert.ErrorIs(t, err, ErrNilParam)
}

// --- Gap 10: BuildCreateRoot change-under-dust suppression ---

func TestBuildCreateRoot_ChangeUnderDust(t *testing.T) {
	_, nodePub := generateTestKeyPair(t)
	payload := []byte("root node payload for dust test")

	// Calculate exactly how much we need so change is below dust limit.
	// estSize = EstimateTxSize(1, 3, len(payload))
	// estFee  = EstimateFee(estSize, 1)
	// totalNeeded = DustLimit + estFee
	// We set FeeUTXO.Amount = totalNeeded + 100 (100 < DustLimit=546, so change is suppressed)
	estSize := EstimateTxSize(1, 3, len(payload))
	estFee := EstimateFee(estSize, 1)
	feeAmount := DustLimit + estFee + 100 // change = 100 sat, below dust

	result, err := BuildCreateRoot(&CreateRootParams{
		NodePubKey: nodePub,
		Payload:    payload,
		FeeUTXO:    testFeeUTXO(t, feeAmount),
		FeeRate:    1,
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Nil(t, result.ChangeUTXO, "change below dust limit should be suppressed (absorbed into fee)")
}

// --- Gap 11: BuildCreateChild ChangeUTXO output ordering (Vout=3) ---

func TestBuildCreateChild_ChangeOutputVout(t *testing.T) {
	_, nodePub := generateTestKeyPair(t)
	parentPriv, parentPub := generateTestKeyPair(t)
	parentTxID := bytes.Repeat([]byte{0xaa}, 32)

	result, err := BuildCreateChild(&CreateChildParams{
		NodePubKey:    nodePub,
		ParentTxID:    parentTxID,
		Payload:       []byte("child payload for vout test"),
		ParentUTXO:    &UTXO{TxID: parentTxID, Vout: 1, Amount: DustLimit, PrivateKey: parentPriv},
		ParentPrivKey: parentPriv,
		FeeUTXO:       testFeeUTXO(t, 100000), // large enough to produce change
		ParentPubKey:  parentPub,
		FeeRate:       1,
	})
	require.NoError(t, err)
	assert.NotNil(t, result.ChangeUTXO, "should produce change output with large fee UTXO")
	assert.Equal(t, uint32(3), result.ChangeUTXO.Vout, "change output must be at Vout=3")
}

// --- Gap 12: ParseOPReturnData with invalid parent TxID length ---

func TestParseOPReturnData_InvalidParentTxIDLength(t *testing.T) {
	pushes := [][]byte{
		MetaFlagBytes,
		bytes.Repeat([]byte{0x02}, CompressedPubKeyLen), // valid P_node length
		{0x01, 0x02, 0x03}, // 3 bytes -- not 0 and not 32
		[]byte("payload"),
	}
	_, _, _, err := ParseOPReturnData(pushes)
	assert.ErrorIs(t, err, ErrInvalidOPReturn)
}

// --- Gap 13: ParseOPReturnData with empty payload ---

func TestParseOPReturnData_EmptyPayload(t *testing.T) {
	pushes := [][]byte{
		MetaFlagBytes,
		bytes.Repeat([]byte{0x02}, CompressedPubKeyLen),
		bytes.Repeat([]byte{0x03}, TxIDLen),
		{}, // empty payload
	}
	_, _, _, err := ParseOPReturnData(pushes)
	assert.ErrorIs(t, err, ErrInvalidOPReturn)
}

// --- Gap 14: EstimateFee zero-size edge case ---

func TestEstimateFee_ZeroSize(t *testing.T) {
	fee := EstimateFee(0, 1)
	// ceil(0 * 1 / 1000) = ceil(0) = 0, but implementation uses (0+999)/1000 = 0
	assert.Equal(t, uint64(0), fee, "zero-size tx should produce zero fee")
}

// --- Gap 15: EstimateTxSize zero inputs/outputs ---

func TestEstimateTxSize_ZeroInputsOutputs(t *testing.T) {
	size := EstimateTxSize(0, 0, 0)
	// Should still return base + opReturn overhead, never negative
	assert.Greater(t, size, 0, "degenerate tx size should still be positive")
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkBuildOPReturnData(b *testing.B) {
	privKey, _ := ec.NewPrivateKey()
	pubKey := privKey.PubKey()
	parentTxID := bytes.Repeat([]byte{0xab}, 32)
	payload := bytes.Repeat([]byte("payload-data"), 100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := BuildOPReturnData(pubKey, parentTxID, payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseOPReturnData(b *testing.B) {
	privKey, _ := ec.NewPrivateKey()
	pubKey := privKey.PubKey()
	parentTxID := bytes.Repeat([]byte{0xab}, 32)
	payload := bytes.Repeat([]byte("payload-data"), 100)

	pushes, err := BuildOPReturnData(pubKey, parentTxID, payload)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, err := ParseOPReturnData(pushes)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBuildParseOPReturnRoundTrip(b *testing.B) {
	privKey, _ := ec.NewPrivateKey()
	pubKey := privKey.PubKey()
	parentTxID := bytes.Repeat([]byte{0xab}, 32)
	payload := bytes.Repeat([]byte("payload-data"), 100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pushes, err := BuildOPReturnData(pubKey, parentTxID, payload)
		if err != nil {
			b.Fatal(err)
		}
		_, _, _, err = ParseOPReturnData(pushes)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBuildCreateRoot(b *testing.B) {
	privKey, _ := ec.NewPrivateKey()
	pubKey := privKey.PubKey()
	payload := bytes.Repeat([]byte("root-payload"), 50)
	feeUTXO := &UTXO{
		TxID:   bytes.Repeat([]byte{0x01}, 32),
		Vout:   0,
		Amount: 100000,
	}

	params := &CreateRootParams{
		NodePubKey: pubKey,
		Payload:    payload,
		FeeUTXO:    feeUTXO,
		FeeRate:    1,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := BuildCreateRoot(params)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBuildCreateChild(b *testing.B) {
	privKey, _ := ec.NewPrivateKey()
	nodePub := privKey.PubKey()
	parentPriv, _ := ec.NewPrivateKey()
	parentPub := parentPriv.PubKey()
	parentTxID := bytes.Repeat([]byte{0xaa}, 32)
	payload := bytes.Repeat([]byte("child-payload"), 50)

	params := &CreateChildParams{
		NodePubKey:    nodePub,
		ParentTxID:    parentTxID,
		Payload:       payload,
		ParentUTXO:    &UTXO{TxID: parentTxID, Vout: 1, Amount: DustLimit, PrivateKey: parentPriv},
		ParentPrivKey: parentPriv,
		FeeUTXO: &UTXO{
			TxID:   bytes.Repeat([]byte{0x01}, 32),
			Vout:   0,
			Amount: 100000,
		},
		ParentPubKey: parentPub,
		FeeRate:      1,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := BuildCreateChild(params)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEstimateFee(b *testing.B) {
	b.Run("small_tx", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			EstimateFee(300, 1)
		}
	})
	b.Run("large_tx", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			EstimateFee(100000, 10)
		}
	})
}

func BenchmarkEstimateTxSize(b *testing.B) {
	b.Run("root_tx", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			EstimateTxSize(1, 3, 200)
		}
	})
	b.Run("child_tx", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			EstimateTxSize(2, 4, 500)
		}
	})
}
