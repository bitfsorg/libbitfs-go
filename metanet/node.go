package metanet

const (
	// CompressedPubKeyLen is the length of a compressed public key.
	CompressedPubKeyLen = 33

	// TxIDLen is the length of a transaction ID.
	TxIDLen = 32

	// MaxLinkDepth is the maximum depth for following soft link chains.
	MaxLinkDepth = 10
)

// NodeType represents the three Metanet node types.
type NodeType int32

const (
	// NodeTypeFile represents a file node.
	NodeTypeFile NodeType = 0
	// NodeTypeDir represents a directory node.
	NodeTypeDir NodeType = 1
	// NodeTypeLink represents a link node (soft link).
	NodeTypeLink NodeType = 2
)

// String returns a human-readable representation of the node type.
func (nt NodeType) String() string {
	switch nt {
	case NodeTypeFile:
		return "FILE"
	case NodeTypeDir:
		return "DIR"
	case NodeTypeLink:
		return "LINK"
	default:
		return "UNKNOWN"
	}
}

// OpType represents the filesystem operation type.
type OpType int32

const (
	// OpCreate creates a new node.
	OpCreate OpType = 0
	// OpUpdate updates an existing node.
	OpUpdate OpType = 1
	// OpDelete marks a node as deleted.
	OpDelete OpType = 2
)

// String returns a human-readable representation of the operation type.
func (op OpType) String() string {
	switch op {
	case OpCreate:
		return "CREATE"
	case OpUpdate:
		return "UPDATE"
	case OpDelete:
		return "DELETE"
	default:
		return "UNKNOWN"
	}
}

// LinkType represents soft link subtypes.
type LinkType int32

const (
	// LinkTypeSoft points to a P_node within the same vault.
	LinkTypeSoft LinkType = 0
	// LinkTypeSoftRemote points to domain/path across vaults.
	LinkTypeSoftRemote LinkType = 1
)

// AccessLevel represents the access control level.
type AccessLevel int32

const (
	// AccessPrivate is private (encrypted, owner-only).
	AccessPrivate AccessLevel = 0
	// AccessFree is publicly readable at no cost.
	AccessFree AccessLevel = 1
	// AccessPaid requires payment to read.
	AccessPaid AccessLevel = 2
)

// ChildEntry represents a directory entry (Unix dirent).
type ChildEntry struct {
	Index    uint32   // Child's index within parent directory
	Name     string   // File/directory name (stored only in parent)
	Type     NodeType // FILE / DIR / LINK
	PubKey   []byte   // Child's P_node (33 bytes compressed)
	Hardened bool     // true = hardened BIP32 derivation (excluded from dir purchase)
}

// Node represents a parsed Metanet node with its payload.
type Node struct {
	TxID        []byte // Transaction ID (32 bytes)
	PNode       []byte // P_node compressed public key (33 bytes)
	ParentTxID  []byte // Parent's TxID (empty for root)
	BlockHeight uint32 // Block height (0 = unconfirmed)

	// Parsed payload fields
	Version        uint32
	Type           NodeType
	Op             OpType
	MimeType       string
	FileSize       uint64
	KeyHash        []byte // SHA256(SHA256(plaintext))
	Access         AccessLevel
	PricePerKB     uint64
	LinkTarget     []byte   // Target P_node for soft links
	LinkType       LinkType
	Timestamp      uint64
	Parent         []byte // Parent P_node
	Index          uint32 // File index within parent
	Children       []ChildEntry
	NextChildIndex uint32
	Domain         string
	Keywords       string
	Description    string
	Metadata       map[string]string
	Encrypted      bool
	PrivateKeyHash []byte
	EncPayload     []byte
	PrivateFileIdx uint32
	OnChain        bool
	ContentTxIDs   [][]byte
	Compression    int32
	CltvHeight     uint32
	RevenueShare   uint32
	NetworkName    string
}

// IsRoot returns true if this node has no parent (root of the filesystem).
func (n *Node) IsRoot() bool {
	return len(n.ParentTxID) == 0
}

// IsDir returns true if this node is a directory.
func (n *Node) IsDir() bool {
	return n.Type == NodeTypeDir
}

// IsFile returns true if this node is a file.
func (n *Node) IsFile() bool {
	return n.Type == NodeTypeFile
}

// IsLink returns true if this node is a link.
func (n *Node) IsLink() bool {
	return n.Type == NodeTypeLink
}

// NodeStore provides access to Metanet node data.
// Implementations may read from local txstore or remote daemon.
type NodeStore interface {
	// GetNodeByPubKey returns the latest version of a node by its P_node.
	// "Latest" = highest block height, then TTOR ordering within same block.
	GetNodeByPubKey(pNode []byte) (*Node, error)

	// GetNodeByTxID returns a specific version of a node.
	GetNodeByTxID(txID []byte) (*Node, error)

	// GetNodeVersions returns all versions of a node, ordered by block height desc.
	GetNodeVersions(pNode []byte) ([]*Node, error)

	// GetChildNodes returns all child nodes referenced in a directory's ChildEntry list.
	GetChildNodes(dirNode *Node) ([]*Node, error)
}
