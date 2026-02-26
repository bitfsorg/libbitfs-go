package metanet

import (
	"fmt"
	"strings"
)

// ResolveResult holds the outcome of a path resolution.
type ResolveResult struct {
	Node   *Node       // Resolved target node
	Entry  *ChildEntry // ChildEntry in parent that references this node (nil for root)
	Parent *Node       // Parent directory node (nil for root)
	Path   []string    // Fully resolved path components
}

// MaxPathComponents is the maximum number of components allowed in a path resolution.
const MaxPathComponents = 256

// MaxTotalLinkFollows is the global budget for total link follows across an
// entire ResolvePath call. Each individual FollowLink call is bounded by
// MaxLinkDepth, but the total across all components is bounded here.
const MaxTotalLinkFollows = 40

// ErrTotalLinkBudgetExceeded indicates the total number of link follows
// across the entire path resolution exceeded MaxTotalLinkFollows.
var ErrTotalLinkBudgetExceeded = fmt.Errorf("total link follow budget exceeded (%d)", MaxTotalLinkFollows)

// ResolvePath resolves a filesystem path starting from a root node.
// Handles directory traversal, soft link following (max depth 10),
// and "." / ".." navigation. ".." cannot escape above the root.
func ResolvePath(store NodeStore, root *Node, pathComponents []string) (*ResolveResult, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: store", ErrNilParam)
	}
	if root == nil {
		return nil, fmt.Errorf("%w: root", ErrNilParam)
	}

	// Empty path returns root
	if len(pathComponents) == 0 {
		return &ResolveResult{
			Node: root,
			Path: []string{},
		}, nil
	}

	if len(pathComponents) > MaxPathComponents {
		return nil, fmt.Errorf("%w: path too deep (%d components, max %d)", ErrInvalidPath, len(pathComponents), MaxPathComponents)
	}

	// Validate path components
	for _, comp := range pathComponents {
		if comp == "" {
			return nil, fmt.Errorf("%w: empty component in path", ErrInvalidPath)
		}
	}

	// Track traversal for ".." navigation
	type stackEntry struct {
		node  *Node
		entry *ChildEntry
		name  string
	}

	stack := []stackEntry{{node: root}}
	current := root
	var currentEntry *ChildEntry
	var resolvedPath []string
	totalLinkFollows := 0

	for _, component := range pathComponents {
		switch component {
		case ".":
			// Stay in current directory
			continue

		case "..":
			// Navigate to parent
			if len(stack) <= 1 {
				// Already at root, ".." stays at root (cannot escape)
				continue
			}
			stack = stack[:len(stack)-1]
			parent := stack[len(stack)-1]
			current = parent.node
			currentEntry = parent.entry
			if len(resolvedPath) > 0 {
				resolvedPath = resolvedPath[:len(resolvedPath)-1]
			}
			continue
		}

		// Current must be a directory to traverse into
		if current.Type != NodeTypeDir {
			return nil, fmt.Errorf("%w: %q is not a directory", ErrNotDirectory, component)
		}

		// Find child by name
		entry, found := FindChild(current, component)
		if !found {
			return nil, fmt.Errorf("%w: %q in directory", ErrChildNotFound, component)
		}

		// Resolve child node
		childNode, err := store.GetNodeByPubKey(entry.PubKey)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrNodeNotFound, err)
		}
		if childNode == nil {
			return nil, fmt.Errorf("%w: child %q", ErrNodeNotFound, component)
		}

		// Follow links if needed, tracking against global budget
		resolvedNode := childNode
		if resolvedNode.Type == NodeTypeLink {
			remaining := MaxLinkDepth
			if MaxTotalLinkFollows-totalLinkFollows < remaining {
				remaining = MaxTotalLinkFollows - totalLinkFollows
			}
			if remaining <= 0 {
				return nil, ErrTotalLinkBudgetExceeded
			}
			resolved, hops, err := followLinkCounted(store, resolvedNode, remaining)
			if err != nil {
				return nil, err
			}
			totalLinkFollows += hops
			if totalLinkFollows > MaxTotalLinkFollows {
				return nil, ErrTotalLinkBudgetExceeded
			}
			resolvedNode = resolved
		}

		stack = append(stack, stackEntry{
			node:  resolvedNode,
			entry: entry,
			name:  component,
		})

		current = resolvedNode
		currentEntry = entry
		resolvedPath = append(resolvedPath, component)
	}

	var parentNode *Node
	if len(stack) > 1 {
		parentNode = stack[len(stack)-2].node
	}

	return &ResolveResult{
		Node:   current,
		Entry:  currentEntry,
		Parent: parentNode,
		Path:   resolvedPath,
	}, nil
}

// followLinkCounted resolves a soft link chain, returning the resolved node
// and the number of link hops taken. maxHops limits the maximum hops allowed.
func followLinkCounted(store NodeStore, linkNode *Node, maxHops int) (*Node, int, error) {
	if linkNode.Type != NodeTypeLink {
		return linkNode, 0, nil
	}

	current := linkNode
	hops := 0
	for hops < maxHops {
		if current.Type != NodeTypeLink {
			return current, hops, nil
		}
		if current.LinkType == LinkTypeSoftRemote {
			return nil, hops, fmt.Errorf("%w: target=%s", ErrRemoteLinkNotSupported, current.Domain)
		}
		if len(current.LinkTarget) == 0 {
			return nil, hops, fmt.Errorf("%w: link has no target", ErrNodeNotFound)
		}

		target, err := store.GetNodeByPubKey(current.LinkTarget)
		if err != nil {
			return nil, hops, fmt.Errorf("%w: %w", ErrNodeNotFound, err)
		}
		if target == nil {
			return nil, hops, fmt.Errorf("%w: link target not found", ErrNodeNotFound)
		}

		hops++
		current = target
	}

	if current.Type == NodeTypeLink {
		return nil, hops, ErrLinkDepthExceeded
	}
	return current, hops, nil
}

// SplitPath splits a path string into components.
// Handles leading/trailing slashes and multiple consecutive slashes.
func SplitPath(path string) ([]string, error) {
	if path == "" {
		return nil, ErrInvalidPath
	}

	// Remove leading slash (absolute path)
	path = strings.TrimPrefix(path, "/")
	// Remove trailing slash
	path = strings.TrimSuffix(path, "/")

	if path == "" {
		// Was just "/" - root
		return []string{}, nil
	}

	parts := strings.Split(path, "/")

	// Filter empty components (from consecutive slashes)
	var result []string
	for _, p := range parts {
		if p != "" {
			result = append(result, p)
		}
	}

	return result, nil
}
