package payment

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed artifacts/bitfsHTLC.json
var htlcArtifactJSON []byte

// Artifact represents a compiled sCrypt contract artifact loaded from JSON.
// The Hex field contains the locking script template with constructor parameter
// placeholders (e.g. <invoiceId>, <capsuleHash>) that are substituted at
// instantiation time.
type Artifact struct {
	Version  int         `json:"version"`
	Contract string      `json:"contract"`
	Hex      string      `json:"hex"`
	ABI      []ABIEntity `json:"abi"`
	MD5      string      `json:"md5"`
}

// ABIEntity describes a constructor or public function in the contract ABI.
type ABIEntity struct {
	Name   string       `json:"name"`
	Type   string       `json:"type"` // "constructor" or "function"
	Params []ParamEntry `json:"params"`
	Index  int          `json:"index,omitempty"`
}

// ParamEntry describes a single parameter in an ABI entity.
type ParamEntry struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// LoadArtifact parses the embedded BitfsHTLC contract artifact JSON and returns
// the Artifact struct. The artifact is compiled from the sCrypt source in
// contracts/bitfsHTLC.scrypt and embedded via go:embed at build time.
func LoadArtifact() (*Artifact, error) {
	var art Artifact
	if err := json.Unmarshal(htlcArtifactJSON, &art); err != nil {
		return nil, fmt.Errorf("parse artifact: %w", err)
	}
	if art.Hex == "" {
		return nil, fmt.Errorf("artifact has empty hex template")
	}
	return &art, nil
}

// Instantiate substitutes constructor parameters into the hex template
// and returns the locking script bytes. The parameter placeholders in the
// compiled sCrypt hex are:
//
//	<invoiceId>   — 16-byte invoice ID (hex-encoded to 32 chars)
//	<capsuleHash> — 32-byte SHA256 capsule hash (hex-encoded to 64 chars)
//	<sellerPkh>   — 20-byte seller pubkey hash (hex-encoded to 40 chars)
//	<buyerPkh>    — 20-byte buyer pubkey hash (hex-encoded to 40 chars)
//	<timeout>     — sCrypt integer (little-endian signed magnitude encoding)
func (a *Artifact) Instantiate(
	invoiceID []byte, // 16 bytes
	capsuleHash []byte, // 32 bytes
	sellerPkh []byte, // 20 bytes
	buyerPkh []byte, // 20 bytes
	timeout uint32,
) ([]byte, error) {
	if len(invoiceID) != InvoiceIDLen {
		return nil, fmt.Errorf("invoiceID must be %d bytes, got %d", InvoiceIDLen, len(invoiceID))
	}
	if len(capsuleHash) != CapsuleHashLen {
		return nil, fmt.Errorf("capsuleHash must be %d bytes, got %d", CapsuleHashLen, len(capsuleHash))
	}
	if len(sellerPkh) != PubKeyHashLen {
		return nil, fmt.Errorf("sellerPkh must be %d bytes, got %d", PubKeyHashLen, len(sellerPkh))
	}
	if len(buyerPkh) != PubKeyHashLen {
		return nil, fmt.Errorf("buyerPkh must be %d bytes, got %d", PubKeyHashLen, len(buyerPkh))
	}

	script := a.Hex
	script = strings.Replace(script, "<invoiceId>", hex.EncodeToString(invoiceID), 1)
	script = strings.Replace(script, "<capsuleHash>", hex.EncodeToString(capsuleHash), 1)
	script = strings.Replace(script, "<sellerPkh>", hex.EncodeToString(sellerPkh), 1)
	script = strings.Replace(script, "<buyerPkh>", hex.EncodeToString(buyerPkh), 1)
	script = strings.Replace(script, "<timeout>", encodeScryptInt(int64(timeout)), 1)

	return hex.DecodeString(script)
}

// encodeScryptInt encodes an integer using sCrypt's little-endian signed
// magnitude format. This matches Bitcoin Script's number encoding:
//   - 0 encodes as "00"
//   - Positive values are little-endian; if the high bit of the last byte
//     is set, an extra 0x00 byte is appended to distinguish from negative
//   - Negative values set the high bit of the last byte as the sign bit
func encodeScryptInt(v int64) string {
	if v == 0 {
		return "00"
	}
	negative := v < 0
	if negative {
		v = -v
	}
	var buf []byte
	for v > 0 {
		buf = append(buf, byte(v&0xff))
		v >>= 8
	}
	// If the high bit of the last byte is set, we need an extra byte
	// to hold the sign bit.
	if buf[len(buf)-1]&0x80 != 0 {
		if negative {
			buf = append(buf, 0x80)
		} else {
			buf = append(buf, 0x00)
		}
	} else if negative {
		buf[len(buf)-1] |= 0x80
	}
	return hex.EncodeToString(buf)
}
