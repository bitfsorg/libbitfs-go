package method42

import (
	"bytes"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// FuzzEncryptDecryptRoundTrip verifies that for any plaintext,
// Encrypt followed by Decrypt returns the original content.
// Tests all three access modes.
func FuzzEncryptDecryptRoundTrip(f *testing.F) {
	f.Add([]byte("hello world"))
	f.Add([]byte(""))
	f.Add([]byte{0})
	f.Add([]byte{0xff, 0xfe, 0xfd})
	f.Add(make([]byte, 4096))

	privKey, err := ec.NewPrivateKey()
	if err != nil {
		f.Fatal(err)
	}
	pubKey := privKey.PubKey()

	f.Fuzz(func(t *testing.T, plaintext []byte) {
		for _, access := range []Access{AccessFree, AccessPrivate, AccessPaid} {
			enc, err := Encrypt(plaintext, privKey, pubKey, access)
			if err != nil {
				t.Fatalf("Encrypt(%s): %v", access, err)
			}

			dec, err := Decrypt(enc.Ciphertext, privKey, pubKey, enc.KeyHash, access)
			if err != nil {
				t.Fatalf("Decrypt(%s): %v", access, err)
			}

			// bytes.Equal treats nil and []byte{} as equal
			if !bytes.Equal(dec.Plaintext, plaintext) {
				if len(plaintext) == 0 && len(dec.Plaintext) == 0 {
					continue
				}
				t.Fatalf("%s round-trip mismatch: got %d bytes, want %d bytes",
					access, len(dec.Plaintext), len(plaintext))
			}

			// Verify key hash consistency
			if !bytes.Equal(dec.KeyHash, enc.KeyHash) {
				t.Fatalf("%s key hash mismatch after round-trip", access)
			}
		}
	})
}

// FuzzDecryptNoPanic ensures Decrypt never panics on arbitrary ciphertext.
func FuzzDecryptNoPanic(f *testing.F) {
	f.Add([]byte{}, []byte("01234567890123456789012345678901"))
	f.Add([]byte{0x00}, []byte("01234567890123456789012345678901"))
	f.Add(make([]byte, MinCiphertextLen), []byte("01234567890123456789012345678901"))

	privKey, err := ec.NewPrivateKey()
	if err != nil {
		f.Fatal(err)
	}
	pubKey := privKey.PubKey()

	f.Fuzz(func(t *testing.T, ciphertext, keyHash []byte) {
		// Must not panic; errors are expected
		Decrypt(ciphertext, privKey, pubKey, keyHash, AccessFree)
		Decrypt(ciphertext, privKey, pubKey, keyHash, AccessPrivate)
	})
}

// FuzzDecryptWithCapsuleNoPanic ensures DecryptWithCapsule never panics.
func FuzzDecryptWithCapsuleNoPanic(f *testing.F) {
	f.Add([]byte{0}, []byte{1}, []byte("01234567890123456789012345678901"))
	f.Add(make([]byte, MinCiphertextLen), make([]byte, 32), make([]byte, 32))

	f.Fuzz(func(t *testing.T, ciphertext, capsule, keyHash []byte) {
		// Use a fixed key pair for fuzzing (only checking for panics).
		priv := FreePrivateKey()
		pub := priv.PubKey()
		DecryptWithCapsule(ciphertext, capsule, keyHash, priv, pub)
	})
}

// FuzzAESGCMDecryptNoPanic ensures the internal aesGCMDecrypt never panics.
func FuzzAESGCMDecryptNoPanic(f *testing.F) {
	f.Add(make([]byte, MinCiphertextLen), make([]byte, 32))
	f.Add([]byte{}, []byte{})
	f.Add(make([]byte, 100), make([]byte, 16))

	f.Fuzz(func(t *testing.T, ciphertext, key []byte) {
		aesGCMDecrypt(ciphertext, key, nil)
	})
}

// FuzzDeriveAESKeyNoPanic ensures DeriveAESKey never panics.
func FuzzDeriveAESKeyNoPanic(f *testing.F) {
	f.Add(make([]byte, 32), make([]byte, 32))
	f.Add([]byte{}, []byte{})
	f.Add([]byte{1}, make([]byte, 32))

	f.Fuzz(func(t *testing.T, sharedX, keyHash []byte) {
		DeriveAESKey(sharedX, keyHash)
	})
}
