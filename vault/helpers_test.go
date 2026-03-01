package vault

import (
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	bsvhash "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/bitfsorg/libbitfs-go/metanet"
)

func TestDetectMimeType(t *testing.T) {
	tests := []struct {
		filename string
		want     string
	}{
		{"readme.txt", "text/plain"},
		{"index.html", "text/html"},
		{"page.htm", "text/html"},
		{"style.css", "text/css"},
		{"app.js", "application/javascript"},
		{"data.json", "application/json"},
		{"feed.xml", "application/xml"},
		{"paper.pdf", "application/pdf"},
		{"logo.png", "image/png"},
		{"photo.jpg", "image/jpeg"},
		{"photo.jpeg", "image/jpeg"},
		{"anim.gif", "image/gif"},
		{"icon.svg", "image/svg+xml"},
		{"video.mp4", "video/mp4"},
		{"song.mp3", "audio/mpeg"},
		{"archive.zip", "application/zip"},
		{"archive.gz", "application/gzip"},
		{"archive.tar", "application/x-tar"},
		{"data.csv", "text/csv"},
		{"notes.md", "text/markdown"},
		// Case insensitivity.
		{"README.TXT", "text/plain"},
		{"Photo.JPG", "image/jpeg"},
		// Unknown extension falls back to http.DetectContentType default.
		{"file.xyz", "text/plain; charset=utf-8"},
		{"noext", "text/plain; charset=utf-8"},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got := DetectMimeType(tt.filename)
			if got != tt.want {
				t.Errorf("DetectMimeType(%q) = %q, want %q", tt.filename, got, tt.want)
			}
		})
	}
}

func TestNodeTypeString(t *testing.T) {
	tests := []struct {
		nt   metanet.NodeType
		want string
	}{
		{metanet.NodeTypeFile, "file"},
		{metanet.NodeTypeDir, "dir"},
		{metanet.NodeTypeLink, "link"},
		{metanet.NodeType(99), "unknown"},
	}

	for _, tt := range tests {
		got := NodeTypeString(tt.nt)
		if got != tt.want {
			t.Errorf("NodeTypeString(%d) = %q, want %q", tt.nt, got, tt.want)
		}
	}
}

func TestAccessString(t *testing.T) {
	tests := []struct {
		al   metanet.AccessLevel
		want string
	}{
		{metanet.AccessPrivate, "private"},
		{metanet.AccessFree, "free"},
		{metanet.AccessPaid, "paid"},
		{metanet.AccessLevel(99), "unknown"},
	}

	for _, tt := range tests {
		got := AccessString(tt.al)
		if got != tt.want {
			t.Errorf("AccessString(%d) = %q, want %q", tt.al, got, tt.want)
		}
	}
}

func TestTxIDBytes(t *testing.T) {
	// Valid 32-byte hex.
	validHex := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	b, err := TxIDBytes(validHex)
	if err != nil {
		t.Fatalf("TxIDBytes(%q) unexpected error: %v", validHex, err)
	}
	if len(b) != 32 {
		t.Errorf("TxIDBytes(%q) length = %d, want 32", validHex, len(b))
	}

	// Invalid hex.
	_, err = TxIDBytes("zzzz")
	if err == nil {
		t.Error("TxIDBytes(invalid hex) expected error")
	}

	// Wrong length (16 bytes instead of 32).
	_, err = TxIDBytes("abcdef0123456789abcdef0123456789")
	if err == nil {
		t.Error("TxIDBytes(16 bytes) expected error")
	}

	// Empty string.
	_, err = TxIDBytes("")
	if err == nil {
		t.Error("TxIDBytes(empty) expected error")
	}
}

func TestMustDecodeHex(t *testing.T) {
	// Valid hex.
	b := mustDecodeHex("abcd")
	if len(b) != 2 || b[0] != 0xab || b[1] != 0xcd {
		t.Errorf("mustDecodeHex(abcd) = %x, want abcd", b)
	}

	// Empty string is valid (returns empty).
	b = mustDecodeHex("")
	if len(b) != 0 {
		t.Errorf("mustDecodeHex(empty) = %x, want empty", b)
	}

	// Invalid hex should panic.
	assert.Panics(t, func() { mustDecodeHex("zzzz") }, "invalid hex should panic")
}

func TestNodeTypeInt(t *testing.T) {
	tests := []struct {
		s    string
		want int32
	}{
		{"dir", int32(metanet.NodeTypeDir)},
		{"link", int32(metanet.NodeTypeLink)},
		{"file", int32(metanet.NodeTypeFile)},
		{"unknown", int32(metanet.NodeTypeFile)}, // default
	}

	for _, tt := range tests {
		got := nodeTypeInt(tt.s)
		if got != tt.want {
			t.Errorf("nodeTypeInt(%q) = %d, want %d", tt.s, got, tt.want)
		}
	}
}

func TestNodeTypeFromString(t *testing.T) {
	tests := []struct {
		s    string
		want metanet.NodeType
	}{
		{"dir", metanet.NodeTypeDir},
		{"link", metanet.NodeTypeLink},
		{"file", metanet.NodeTypeFile},
		{"other", metanet.NodeTypeFile}, // default
	}

	for _, tt := range tests {
		got := nodeTypeFromString(tt.s)
		if got != tt.want {
			t.Errorf("nodeTypeFromString(%q) = %d, want %d", tt.s, got, tt.want)
		}
	}
}

func TestMustDecompressPubKey(t *testing.T) {
	// Invalid hex should panic.
	assert.Panics(t, func() { mustDecompressPubKey("zzzz") }, "invalid hex should panic")

	// Valid hex but not a valid pubkey should panic.
	assert.Panics(t, func() {
		mustDecompressPubKey("000000000000000000000000000000000000000000000000000000000000000000")
	}, "zero key should panic")
}

func TestPubKeyHash_MatchesGoSDK(t *testing.T) {
	// Generate a random key and verify our pubKeyHash matches go-sdk's Hash160.
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	pub := privKey.PubKey()
	got := pubKeyHash(pub)

	// go-sdk's canonical Hash160 = RIPEMD160(SHA256(data))
	want := bsvhash.Hash160(pub.Compressed())

	assert.Equal(t, want, got, "pubKeyHash must match go-sdk Hash160")
	assert.Len(t, got, 20, "HASH160 output must be 20 bytes")
}

func TestPubKeyHash_Deterministic(t *testing.T) {
	// Same key must produce the same hash every time.
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)

	pub := privKey.PubKey()
	h1 := pubKeyHash(pub)
	h2 := pubKeyHash(pub)

	assert.Equal(t, h1, h2, "pubKeyHash must be deterministic")
}

func TestPubKeyHash_DifferentKeys(t *testing.T) {
	// Different keys must produce different hashes.
	priv1, err := ec.NewPrivateKey()
	require.NoError(t, err)
	priv2, err := ec.NewPrivateKey()
	require.NoError(t, err)

	h1 := pubKeyHash(priv1.PubKey())
	h2 := pubKeyHash(priv2.PubKey())

	assert.NotEqual(t, h1, h2, "different keys must produce different hashes")
}
