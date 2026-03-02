package method42

// zeroize overwrites a byte slice with zeros to minimize the window during which
// sensitive key material remains in heap memory. While Go's GC and compiler
// optimizations cannot guarantee complete erasure, explicit zeroing reduces the
// exposure window for memory forensics attacks.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
