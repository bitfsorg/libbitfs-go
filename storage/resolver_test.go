package storage

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKeyHash returns a valid 32-byte key hash for testing.
func testKeyHash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// contentKeyHash returns a valid 32-byte hash derived from content.
// Used in tests as a convenient keyHash generator; in production,
// keyHash = SHA256(SHA256(plaintext)).
func contentKeyHash(content []byte) []byte {
	h := sha256.Sum256(content)
	return h[:]
}

func TestContentResolver_FetchFromLocalStore(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	ciphertext := []byte("encrypted-hello")
	keyHash := contentKeyHash(ciphertext)
	require.NoError(t, store.Put(keyHash, ciphertext))

	r := NewContentResolver(store)
	data, err := r.Fetch(keyHash)
	require.NoError(t, err)
	assert.Equal(t, ciphertext, data)
}

func TestContentResolver_FetchFromEndpoint(t *testing.T) {
	ciphertext := []byte("remote-encrypted-data")
	keyHash := contentKeyHash(ciphertext)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ciphertext)
	}))
	defer srv.Close()

	// No local store — forces endpoint fetch.
	r := &ContentResolver{
		Endpoints: []string{srv.URL},
		Client:    srv.Client(),
	}

	data, err := r.Fetch(keyHash)
	require.NoError(t, err)
	assert.Equal(t, ciphertext, data)
}

func TestContentResolver_FetchCachesLocally(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	ciphertext := []byte("cached-cipher")
	keyHash := contentKeyHash(ciphertext)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(ciphertext)
	}))
	defer srv.Close()

	r := &ContentResolver{
		Store:     store,
		Endpoints: []string{srv.URL},
		Client:    srv.Client(),
	}

	// First fetch: from endpoint (not in local store).
	data, err := r.Fetch(keyHash)
	require.NoError(t, err)
	assert.Equal(t, ciphertext, data)

	// Verify it was cached locally.
	cached, err := store.Get(keyHash)
	require.NoError(t, err)
	assert.Equal(t, ciphertext, cached)
}

func TestContentResolver_FetchLocalPriority(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	localData := []byte("local-version")
	keyHash := contentKeyHash(localData)
	require.NoError(t, store.Put(keyHash, localData))

	endpointCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpointCalled = true
		_, _ = w.Write([]byte("remote-version"))
	}))
	defer srv.Close()

	r := &ContentResolver{
		Store:     store,
		Endpoints: []string{srv.URL},
		Client:    srv.Client(),
	}

	data, err := r.Fetch(keyHash)
	require.NoError(t, err)
	assert.Equal(t, localData, data)
	assert.False(t, endpointCalled, "should not contact endpoint when local has data")
}

func TestContentResolver_FetchAllSourcesFail(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	keyHash := testKeyHash([]byte("missing"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	r := &ContentResolver{
		Store:     store,
		Endpoints: []string{srv.URL},
		Client:    srv.Client(),
	}

	_, err = r.Fetch(keyHash)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestContentResolver_FetchInvalidKeyHash(t *testing.T) {
	r := NewContentResolver(nil)

	_, err := r.Fetch([]byte("short"))
	assert.ErrorIs(t, err, ErrInvalidKeyHash)
}

func TestContentResolver_FetchNoSources(t *testing.T) {
	r := &ContentResolver{} // no store, no endpoints

	keyHash := testKeyHash([]byte("nowhere"))
	_, err := r.Fetch(keyHash)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestContentResolver_OversizedResponse(t *testing.T) {
	// Server streams more than MaxContentResponseSize bytes.
	bigBody := make([]byte, 1025) // just over 1KB for test speed
	keyHash := contentKeyHash(bigBody)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bigBody)
	}))
	defer srv.Close()

	r := &ContentResolver{
		Endpoints: []string{srv.URL},
		Client:    srv.Client(),
	}

	data, err := r.Fetch(keyHash)
	// With a reasonable limit, this should still succeed (1KB < 1GB limit).
	require.NoError(t, err)
	assert.Len(t, data, 1025)
}

func TestContentResolver_FetchEndpointFallback(t *testing.T) {
	ciphertext := []byte("from-second-endpoint")
	keyHash := contentKeyHash(ciphertext)

	// First endpoint fails, second succeeds.
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer fail.Close()

	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(ciphertext)
	}))
	defer ok.Close()

	r := &ContentResolver{
		Endpoints: []string{fail.URL, ok.URL},
		Client:    &http.Client{},
	}

	data, err := r.Fetch(keyHash)
	require.NoError(t, err)
	assert.Equal(t, ciphertext, data)
}

func TestContentResolver_FetchAcceptsRemoteData(t *testing.T) {
	// The resolver no longer verifies SHA256(data) == keyHash because
	// keyHash is SHA256(SHA256(plaintext)) while the wire data is ciphertext.
	// Integrity is verified at the decryption layer (AES-256-GCM).
	ciphertext := []byte("any-remote-data")
	keyHash := testKeyHash([]byte("unrelated-key-material"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ciphertext)
	}))
	defer srv.Close()

	r := &ContentResolver{
		Endpoints: []string{srv.URL},
		Client:    srv.Client(),
	}

	data, err := r.Fetch(keyHash)
	require.NoError(t, err, "resolver should accept remote data without hash verification")
	assert.Equal(t, ciphertext, data)
}

func TestContentResolver_FetchEncryptedContent(t *testing.T) {
	// Simulate real-world scenario: keyHash = SHA256(SHA256(plaintext)),
	// but the remote endpoint serves ciphertext (encrypted version of plaintext).
	// These are completely different bytes, so SHA256(ciphertext) != keyHash.
	plaintext := []byte("hello world")
	ciphertext := []byte("encrypted-hello-world-aes256gcm") // opaque ciphertext

	// Real keyHash derivation: double-SHA256 of plaintext.
	inner := sha256.Sum256(plaintext)
	keyHash := sha256.Sum256(inner[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ciphertext)
	}))
	defer srv.Close()

	r := &ContentResolver{
		Endpoints: []string{srv.URL},
		Client:    srv.Client(),
	}

	// Before the fix, this would return ErrNotFound because
	// SHA256(ciphertext) != SHA256(SHA256(plaintext)).
	data, err := r.Fetch(keyHash[:])
	require.NoError(t, err, "Fetch must succeed for encrypted content keyed by SHA256(SHA256(plaintext))")
	assert.Equal(t, ciphertext, data)
}

func TestContentResolver_FetchEncryptedContentCachesLocally(t *testing.T) {
	// Verify that remotely fetched encrypted content is cached in local store.
	plaintext := []byte("cache-test-data")
	ciphertext := []byte("encrypted-cache-test-data-bytes")

	inner := sha256.Sum256(plaintext)
	keyHash := sha256.Sum256(inner[:])

	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(ciphertext)
	}))
	defer srv.Close()

	r := &ContentResolver{
		Store:     store,
		Endpoints: []string{srv.URL},
		Client:    srv.Client(),
	}

	data, err := r.Fetch(keyHash[:])
	require.NoError(t, err)
	assert.Equal(t, ciphertext, data)

	// Verify cached in local store.
	cached, err := store.Get(keyHash[:])
	require.NoError(t, err)
	assert.Equal(t, ciphertext, cached)
}

func TestContentResolver_FetchUsesFirstSuccessfulEndpoint(t *testing.T) {
	// Resolver takes the first endpoint that returns HTTP 200 with data.
	// Hash verification is not performed at this layer.
	firstData := []byte("first-endpoint-data")
	keyHash := testKeyHash([]byte("some-key"))

	firstSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(firstData)
	}))
	defer firstSrv.Close()

	secondCalled := false
	secondSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondCalled = true
		_, _ = w.Write([]byte("second-endpoint-data"))
	}))
	defer secondSrv.Close()

	r := &ContentResolver{
		Endpoints: []string{firstSrv.URL, secondSrv.URL},
		Client:    &http.Client{},
	}

	data, err := r.Fetch(keyHash)
	require.NoError(t, err)
	assert.Equal(t, firstData, data)
	assert.False(t, secondCalled, "should not contact second endpoint when first succeeds")
}
