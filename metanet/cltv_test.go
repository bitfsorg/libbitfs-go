package metanet

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckCLTVAccess(t *testing.T) {
	tests := []struct {
		name          string
		cltvHeight    uint32
		currentHeight uint32
		expected      CLTVResult
	}{
		{"no restriction", 0, 0, CLTVAllowed},
		{"no restriction with height", 0, 100000, CLTVAllowed},
		{"height reached exactly", 500000, 500000, CLTVAllowed},
		{"height exceeded", 500000, 500001, CLTVAllowed},
		{"height not reached", 500000, 499999, CLTVDenied},
		{"height 1 not reached at 0", 1, 0, CLTVDenied},
		{"max height", 4294967295, 4294967295, CLTVAllowed},
		{"max height not reached", 4294967295, 4294967294, CLTVDenied},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &Node{CltvHeight: tt.cltvHeight}
			result := CheckCLTVAccess(node, tt.currentHeight)
			assert.Equal(t, tt.expected, result)
		})
	}
}
