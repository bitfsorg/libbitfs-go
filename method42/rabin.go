package method42

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
)

// RabinKeyPair holds a Rabin signature key pair.
type RabinKeyPair struct {
	P *big.Int // private prime p ≡ 3 (mod 4)
	Q *big.Int // private prime q ≡ 3 (mod 4)
	N *big.Int // public modulus n = p * q
}

// GenerateRabinKey generates a Rabin key pair with primes of bitSize bits each.
func GenerateRabinKey(bitSize int) (*RabinKeyPair, error) {
	p, err := generateBlumPrime(bitSize)
	if err != nil {
		return nil, fmt.Errorf("generating p: %w", err)
	}
	q, err := generateBlumPrime(bitSize)
	if err != nil {
		return nil, fmt.Errorf("generating q: %w", err)
	}
	if p.Cmp(q) == 0 {
		return nil, fmt.Errorf("method42: generated identical primes (retry)")
	}
	n := new(big.Int).Mul(p, q)
	return &RabinKeyPair{P: p, Q: q, N: n}, nil
}

// generateBlumPrime generates a random prime p ≡ 3 (mod 4).
func generateBlumPrime(bitSize int) (*big.Int, error) {
	three := big.NewInt(3)
	four := big.NewInt(4)
	for {
		p, err := rand.Prime(rand.Reader, bitSize)
		if err != nil {
			return nil, err
		}
		if new(big.Int).Mod(p, four).Cmp(three) == 0 {
			return p, nil
		}
	}
}

// maxRabinPaddingIterations is the maximum number of padding attempts when
// searching for a quadratic residue during Rabin signing.
const maxRabinPaddingIterations = 1_000_000

// RabinSign signs a message using the Rabin signature scheme.
// Returns (S, U) where S is the signature and U is the padding.
func RabinSign(key *RabinKeyPair, message []byte) (*big.Int, []byte, error) {
	// Find padding U such that H(message || U) is a quadratic residue mod n
	for counter := uint32(0); counter < maxRabinPaddingIterations; counter++ {
		pad := make([]byte, 4)
		binary.BigEndian.PutUint32(pad, counter)

		h := rabinHash(message, pad, key.N)

		// Check if h is a quadratic residue mod p and mod q
		if !isQuadraticResidue(h, key.P) || !isQuadraticResidue(h, key.Q) {
			continue
		}

		// Compute square root using CRT
		sp := modSqrtBlum(h, key.P)
		sq := modSqrtBlum(h, key.Q)

		// CRT reconstruction
		sig := crt(sp, sq, key.P, key.Q, key.N)
		return sig, pad, nil
	}
	return nil, nil, fmt.Errorf("method42: rabin sign failed after %d padding iterations", maxRabinPaddingIterations)
}

// RabinVerify verifies a Rabin signature using only the public modulus n.
func RabinVerify(n *big.Int, message []byte, sig *big.Int, pad []byte) bool {
	h := rabinHash(message, pad, n)
	s2 := new(big.Int).Mul(sig, sig)
	s2.Mod(s2, n)
	return s2.Cmp(h) == 0
}

func rabinHash(message, padding []byte, n *big.Int) *big.Int {
	combined := make([]byte, 0, len(message)+len(padding))
	combined = append(combined, message...)
	combined = append(combined, padding...)
	hash := sha256.Sum256(combined)
	h := new(big.Int).SetBytes(hash[:])
	h.Mod(h, n)
	return h
}

func isQuadraticResidue(a, p *big.Int) bool {
	exp := new(big.Int).Sub(p, big.NewInt(1))
	exp.Rsh(exp, 1)
	result := new(big.Int).Exp(a, exp, p)
	return result.Cmp(big.NewInt(1)) == 0
}

func modSqrtBlum(a, p *big.Int) *big.Int {
	exp := new(big.Int).Add(p, big.NewInt(1))
	exp.Rsh(exp, 2)
	return new(big.Int).Exp(a, exp, p)
}

func crt(sp, sq, p, q, n *big.Int) *big.Int {
	qInv := new(big.Int).ModInverse(q, p)
	pInv := new(big.Int).ModInverse(p, q)

	t1 := new(big.Int).Mul(sp, q)
	t1.Mul(t1, qInv)

	t2 := new(big.Int).Mul(sq, p)
	t2.Mul(t2, pInv)

	result := new(big.Int).Add(t1, t2)
	result.Mod(result, n)
	return result
}

// --- Serialization ---

// SerializeRabinSignature encodes (S, U) for TLV storage.
func SerializeRabinSignature(sig *big.Int, pad []byte) []byte {
	sBytes := sig.Bytes()
	buf := make([]byte, 4+len(sBytes)+4+len(pad))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(sBytes)))
	copy(buf[4:4+len(sBytes)], sBytes)
	offset := 4 + len(sBytes)
	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(pad)))
	copy(buf[offset+4:], pad)
	return buf
}

// DeserializeRabinSignature decodes (S, U) from TLV.
func DeserializeRabinSignature(data []byte) (*big.Int, []byte, error) {
	if len(data) < 8 {
		return nil, nil, fmt.Errorf("rabin signature data too short")
	}
	sLen := int(binary.BigEndian.Uint32(data[0:4]))
	if 4+sLen+4 > len(data) {
		return nil, nil, fmt.Errorf("rabin signature S truncated")
	}
	sig := new(big.Int).SetBytes(data[4 : 4+sLen])
	offset := 4 + sLen
	uLen := int(binary.BigEndian.Uint32(data[offset : offset+4]))
	if offset+4+uLen > len(data) {
		return nil, nil, fmt.Errorf("rabin signature U truncated")
	}
	pad := make([]byte, uLen)
	copy(pad, data[offset+4:offset+4+uLen])
	return sig, pad, nil
}

// SerializeRabinPubKey encodes modulus n for TLV storage.
func SerializeRabinPubKey(n *big.Int) []byte {
	return n.Bytes()
}

// DeserializeRabinPubKey decodes modulus n from TLV.
func DeserializeRabinPubKey(data []byte) (*big.Int, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("rabin pubkey data empty")
	}
	return new(big.Int).SetBytes(data), nil
}
