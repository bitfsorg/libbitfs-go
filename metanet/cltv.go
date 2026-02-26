package metanet

// CLTVResult indicates whether content access is allowed based on block height.
type CLTVResult int

const (
	// CLTVAllowed means no CLTV restriction or height has been reached.
	CLTVAllowed CLTVResult = 0
	// CLTVDenied means the required block height has not been reached.
	CLTVDenied CLTVResult = 1
)

// CheckCLTVAccess checks if content is accessible at the given block height.
// Returns CLTVAllowed if cltv_height is 0 (no restriction) or currentHeight >= cltv_height.
func CheckCLTVAccess(node *Node, currentHeight uint32) CLTVResult {
	if node.CltvHeight == 0 {
		return CLTVAllowed
	}
	if currentHeight >= node.CltvHeight {
		return CLTVAllowed
	}
	return CLTVDenied
}
