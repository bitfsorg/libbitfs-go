package method42

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateRabinKey(t *testing.T) {
	key, err := GenerateRabinKey(1024)
	require.NoError(t, err)
	require.NotNil(t, key)

	// p and q should be primes ≡ 3 mod 4
	assert.True(t, key.P.ProbablyPrime(20))
	assert.True(t, key.Q.ProbablyPrime(20))
	assert.Equal(t, int64(3), new(big.Int).Mod(key.P, big.NewInt(4)).Int64())
	assert.Equal(t, int64(3), new(big.Int).Mod(key.Q, big.NewInt(4)).Int64())

	// n = p * q
	expected := new(big.Int).Mul(key.P, key.Q)
	assert.Equal(t, 0, expected.Cmp(key.N))
}

func TestRabinSignVerify(t *testing.T) {
	key, err := GenerateRabinKey(1024)
	require.NoError(t, err)

	message := []byte("Hello, BitFS content authentication!")
	S, U, err := RabinSign(key, message)
	require.NoError(t, err)

	assert.True(t, RabinVerify(key.N, message, S, U))
}

func TestRabinVerify_TamperedMessage(t *testing.T) {
	key, err := GenerateRabinKey(1024)
	require.NoError(t, err)

	message := []byte("original message")
	S, U, err := RabinSign(key, message)
	require.NoError(t, err)

	tampered := []byte("tampered message")
	assert.False(t, RabinVerify(key.N, tampered, S, U))
}

func TestRabinSignature_Serialization(t *testing.T) {
	key, err := GenerateRabinKey(1024)
	require.NoError(t, err)

	message := []byte("serialization test")
	S, U, err := RabinSign(key, message)
	require.NoError(t, err)

	// Serialize
	data := SerializeRabinSignature(S, U)
	assert.NotEmpty(t, data)

	// Deserialize
	S2, U2, err := DeserializeRabinSignature(data)
	require.NoError(t, err)
	assert.Equal(t, 0, S.Cmp(S2))
	assert.Equal(t, U, U2)

	// Verify with deserialized values
	assert.True(t, RabinVerify(key.N, message, S2, U2))
}

func TestRabinPubKey_Serialization(t *testing.T) {
	key, err := GenerateRabinKey(1024)
	require.NoError(t, err)

	data := SerializeRabinPubKey(key.N)
	n2, err := DeserializeRabinPubKey(data)
	require.NoError(t, err)
	assert.Equal(t, 0, key.N.Cmp(n2))
}

func TestRabinSign_MultipleMessages(t *testing.T) {
	key, err := GenerateRabinKey(1024)
	require.NoError(t, err)

	messages := [][]byte{
		[]byte("message 1"),
		[]byte("message 2"),
		[]byte(""),
		make([]byte, 10000), // large message
	}

	for _, msg := range messages {
		S, U, err := RabinSign(key, msg)
		require.NoError(t, err)
		assert.True(t, RabinVerify(key.N, msg, S, U), "failed for message len=%d", len(msg))
	}
}

func BenchmarkRabinSign_1024(b *testing.B) {
	key, _ := GenerateRabinKey(1024)
	msg := make([]byte, 1024)
	rand.Read(msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RabinSign(key, msg)
	}
}

func BenchmarkRabinVerify_1024(b *testing.B) {
	key, _ := GenerateRabinKey(1024)
	msg := make([]byte, 1024)
	rand.Read(msg)
	S, U, _ := RabinSign(key, msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RabinVerify(key.N, msg, S, U)
	}
}
