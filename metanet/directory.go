package metanet

import (
	"bytes"
	"fmt"
	"strings"
)

// ListDirectory returns the ChildEntry list of a directory node.
// Returns error if the node is not a directory.
func ListDirectory(node *Node) ([]ChildEntry, error) {
	if node == nil {
		return nil, fmt.Errorf("%w: node", ErrNilParam)
	}
	if node.Type != NodeTypeDir {
		return nil, fmt.Errorf("%w: node type is %s", ErrNotDirectory, node.Type)
	}
	// Return a copy to prevent external mutation
	result := make([]ChildEntry, len(node.Children))
	copy(result, node.Children)
	return result, nil
}

// FindChild finds a child by name in a directory node's children list.
func FindChild(dirNode *Node, name string) (*ChildEntry, bool) {
	if dirNode == nil || dirNode.Type != NodeTypeDir {
		return nil, false
	}
	for i := range dirNode.Children {
		if dirNode.Children[i].Name == name {
			return &dirNode.Children[i], true
		}
	}
	return nil, false
}

// AddChild adds a new ChildEntry to a directory node.
// Allocates the next child index and increments NextChildIndex.
func AddChild(dirNode *Node, name string, nodeType NodeType, pubKey []byte, hardened bool) (*ChildEntry, error) {
	if dirNode == nil {
		return nil, fmt.Errorf("%w: dirNode", ErrNilParam)
	}
	if dirNode.Type != NodeTypeDir {
		return nil, fmt.Errorf("%w: node type is %s", ErrNotDirectory, dirNode.Type)
	}
	if err := validateChildName(name); err != nil {
		return nil, err
	}
	if len(pubKey) != CompressedPubKeyLen {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidPubKey, len(pubKey))
	}

	// Check for duplicate name
	for _, child := range dirNode.Children {
		if child.Name == name {
			return nil, fmt.Errorf("%w: %q", ErrChildExists, name)
		}
	}

	// Reject hard links to directories (spec section 4.3).
	// A hard link is when a new entry shares a PubKey with an existing entry.
	if nodeType == NodeTypeDir {
		for _, child := range dirNode.Children {
			if bytes.Equal(child.PubKey, pubKey) {
				return nil, fmt.Errorf("%w: cannot hard-link directories", ErrHardLinkToDirectory)
			}
		}
	}

	entry := ChildEntry{
		Index:    dirNode.NextChildIndex,
		Name:     name,
		Type:     nodeType,
		PubKey:   make([]byte, CompressedPubKeyLen),
		Hardened: hardened,
	}
	copy(entry.PubKey, pubKey)

	dirNode.Children = append(dirNode.Children, entry)
	dirNode.NextChildIndex++
	recomputeMerkleRoot(dirNode)

	return &dirNode.Children[len(dirNode.Children)-1], nil
}

// RemoveChild removes a ChildEntry by name from a directory node.
// Does NOT decrement NextChildIndex (deleted indices are never reused).
func RemoveChild(dirNode *Node, name string) error {
	if dirNode == nil {
		return fmt.Errorf("%w: dirNode", ErrNilParam)
	}
	if dirNode.Type != NodeTypeDir {
		return fmt.Errorf("%w: node type is %s", ErrNotDirectory, dirNode.Type)
	}

	for i, child := range dirNode.Children {
		if child.Name == name {
			dirNode.Children = append(dirNode.Children[:i], dirNode.Children[i+1:]...)
			recomputeMerkleRoot(dirNode)
			return nil
		}
	}

	return fmt.Errorf("%w: %q", ErrChildNotFound, name)
}

// RenameChild renames a ChildEntry within a directory.
func RenameChild(dirNode *Node, oldName, newName string) error {
	if dirNode == nil {
		return fmt.Errorf("%w: dirNode", ErrNilParam)
	}
	if dirNode.Type != NodeTypeDir {
		return fmt.Errorf("%w: node type is %s", ErrNotDirectory, dirNode.Type)
	}
	if err := validateChildName(newName); err != nil {
		return err
	}

	// Check new name doesn't already exist
	for _, child := range dirNode.Children {
		if child.Name == newName {
			return fmt.Errorf("%w: %q", ErrChildExists, newName)
		}
	}

	// Find and rename
	for i := range dirNode.Children {
		if dirNode.Children[i].Name == oldName {
			dirNode.Children[i].Name = newName
			recomputeMerkleRoot(dirNode)
			return nil
		}
	}

	return fmt.Errorf("%w: %q", ErrChildNotFound, oldName)
}

// NextChildIndex returns the next available child index for a directory.
// This is the value that would be assigned to the next added child.
func NextChildIndex(dirNode *Node) (uint32, error) {
	if dirNode == nil {
		return 0, fmt.Errorf("%w: dirNode", ErrNilParam)
	}
	if dirNode.Type != NodeTypeDir {
		return 0, fmt.Errorf("%w: node type is %s", ErrNotDirectory, dirNode.Type)
	}
	return dirNode.NextChildIndex, nil
}

// recomputeMerkleRoot updates the node's MerkleRoot from its current Children.
func recomputeMerkleRoot(node *Node) {
	node.MerkleRoot = ComputeDirectoryMerkleRoot(node.Children)
}

// MaxChildNameLen is the maximum length of a directory entry name in bytes.
const MaxChildNameLen = 255

// validateChildName checks that a name is valid for a directory entry.
func validateChildName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: name is empty", ErrInvalidName)
	}
	// Max child name: 255 bytes (fits uint8, well under uint16 serialization limit).
	if len(name) > MaxChildNameLen {
		return fmt.Errorf("%w: name too long (%d bytes, max %d)", ErrInvalidName, len(name), MaxChildNameLen)
	}
	if strings.Contains(name, "/") {
		return fmt.Errorf("%w: name contains path separator", ErrInvalidName)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("%w: name is reserved", ErrInvalidName)
	}
	if strings.ContainsAny(name, "\x00") {
		return fmt.Errorf("%w: name contains null byte", ErrInvalidName)
	}
	return nil
}
