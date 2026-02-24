package metanet

import (
	"fmt"
)

// FollowLink resolves a soft link to its target node.
// SOFT: looks up target P_node for latest version.
// SOFT_REMOTE: returns error (requires external resolution via DNS/Paymail).
// Follows chains up to maxDepth (default MaxLinkDepth=10).
func FollowLink(store NodeStore, linkNode *Node, maxDepth int) (*Node, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: store", ErrNilParam)
	}
	if linkNode == nil {
		return nil, fmt.Errorf("%w: linkNode", ErrNilParam)
	}
	if linkNode.Type != NodeTypeLink {
		return nil, fmt.Errorf("%w: node type is %s", ErrNotLink, linkNode.Type)
	}
	if maxDepth <= 0 {
		maxDepth = MaxLinkDepth
	}

	current := linkNode
	for depth := 0; depth < maxDepth; depth++ {
		if current.Type != NodeTypeLink {
			// Resolved to a non-link node
			return current, nil
		}

		if current.LinkType == LinkTypeSoftRemote {
			return nil, fmt.Errorf("%w: target=%s", ErrRemoteLinkNotSupported, current.Domain)
		}

		// Soft link: look up target by P_node
		if len(current.LinkTarget) == 0 {
			return nil, fmt.Errorf("%w: link has no target", ErrNodeNotFound)
		}

		target, err := store.GetNodeByPubKey(current.LinkTarget)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrNodeNotFound, err)
		}
		if target == nil {
			return nil, fmt.Errorf("%w: link target not found", ErrNodeNotFound)
		}

		current = target
	}

	// If we're still on a link after maxDepth iterations, the chain is too deep
	if current.Type == NodeTypeLink {
		return nil, ErrLinkDepthExceeded
	}

	return current, nil
}

// LatestVersion selects the latest version from a list of nodes with the same P_node.
// Ordering: highest block height wins; within the same block, TTOR ordering
// (Topological Transaction Ordering Rule: last in block wins, approximated by
// higher TxID index / later StoredTx).
func LatestVersion(nodes []*Node) *Node {
	if len(nodes) == 0 {
		return nil
	}

	best := nodes[0]
	for _, n := range nodes[1:] {
		if n == nil {
			continue
		}
		if best == nil {
			best = n
			continue
		}
		if n.BlockHeight > best.BlockHeight {
			best = n
		} else if n.BlockHeight == best.BlockHeight {
			// Same block: TTOR - later in block wins.
			// We approximate this by comparing Timestamp (which could be set
			// to the tx's position index in the block). If timestamps are equal,
			// we compare TxID bytes as a tiebreaker (higher TxID bytes = later).
			if n.Timestamp > best.Timestamp {
				best = n
			} else if n.Timestamp == best.Timestamp {
				if compareTxIDs(n.TxID, best.TxID) > 0 {
					best = n
				}
			}
		}
	}

	return best
}

// compareTxIDs compares two TxIDs lexicographically.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func compareTxIDs(a, b []byte) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

// InheritPricePerKB walks up the directory tree to find the effective price.
// Checks current node, then parent, then grandparent, etc. until root.
// Returns 0 if no price is set anywhere in the ancestry.
func InheritPricePerKB(store NodeStore, node *Node) (uint64, error) {
	if store == nil {
		return 0, fmt.Errorf("%w: store", ErrNilParam)
	}
	if node == nil {
		return 0, fmt.Errorf("%w: node", ErrNilParam)
	}

	current := node
	for depth := 0; depth <= MaxLinkDepth; depth++ {
		if current.PricePerKB > 0 {
			return current.PricePerKB, nil
		}

		// No parent means root; stop
		if len(current.Parent) == 0 {
			return 0, nil
		}

		parent, err := store.GetNodeByPubKey(current.Parent)
		if err != nil {
			return 0, fmt.Errorf("%w: %w", ErrNodeNotFound, err)
		}
		if parent == nil {
			return 0, nil
		}

		current = parent
	}

	return 0, fmt.Errorf("%w: price inheritance exceeded max depth", ErrLinkDepthExceeded)
}
