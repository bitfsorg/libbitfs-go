package paymail

import (
	"crypto/sha256"
	"encoding/hex"
)

// ComputeBRFCID computes a BRFC (Bitcoin Request for Comments) ID per the BRC
// standard. The ID is derived from the double-SHA256 hash of the concatenation
// of title, author, and version strings, truncated to the first 6 bytes (12
// hex characters).
//
//	ID = hex(SHA256d(title + author + version))[:12]
//
// SHA256d denotes SHA256(SHA256(x)).
func ComputeBRFCID(title, author, version string) string {
	data := []byte(title + author + version)
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return hex.EncodeToString(second[:6])
}

// BitFS-specific BRFC capability IDs, advertised in the Paymail
// .well-known/bsvalias response to signal BitFS protocol support.
var (
	BRFCBitFSBrowse = ComputeBRFCID("BitFS Browse", "BitFS", "1.0")
	BRFCBitFSBuy    = ComputeBRFCID("BitFS Buy", "BitFS", "1.0")
	BRFCBitFSSell   = ComputeBRFCID("BitFS Sell", "BitFS", "1.0")
)
