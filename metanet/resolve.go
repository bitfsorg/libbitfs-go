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
			return nil, fmt.Errorf("%w: %v", ErrNodeNotFound, err)
		}
		if childNode == nil {
			return nil, fmt.Errorf("%w: child %q", ErrNodeNotFound, component)
		}

		// Follow links if needed
		resolvedNode := childNode
		if resolvedNode.Type == NodeTypeLink {
			resolved, err := FollowLink(store, resolvedNode, MaxLinkDepth)
			if err != nil {
				return nil, err
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
