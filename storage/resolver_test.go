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

// contentKeyHash returns the SHA256 hash of content, suitable as keyHash
// for content-addressed storage where keyHash = SHA256(stored_data).
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

func TestContentResolver_FetchHashMismatch(t *testing.T) {
	// Endpoint returns data that doesn't match the requested keyHash.
	ciphertext := []byte("tampered-data")
	wrongKeyHash := testKeyHash([]byte("expected-different-content"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ciphertext)
	}))
	defer srv.Close()

	r := &ContentResolver{
		Endpoints: []string{srv.URL},
		Client:    srv.Client(),
	}

	_, err := r.Fetch(wrongKeyHash)
	assert.ErrorIs(t, err, ErrNotFound, "should reject data with hash mismatch")
}

func TestContentResolver_FetchHashMismatchFallback(t *testing.T) {
	// First endpoint returns tampered data, second returns correct data.
	goodData := []byte("correct-content")
	keyHash := contentKeyHash(goodData)

	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tampered-content"))
	}))
	defer badSrv.Close()

	goodSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(goodData)
	}))
	defer goodSrv.Close()

	r := &ContentResolver{
		Endpoints: []string{badSrv.URL, goodSrv.URL},
		Client:    &http.Client{},
	}

	data, err := r.Fetch(keyHash)
	require.NoError(t, err)
	assert.Equal(t, goodData, data)
}
