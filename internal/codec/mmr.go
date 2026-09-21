package codec

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"unicode/utf8"
)

const DomainOutputMMRV1 = "TRUEOPEN_OUTPUT_MMR_V1"

// MMR is an append-only MMR_ROOT_V1 accumulator. It retains only the peaks;
// leaf indexes are assigned in append order and roots fold peaks right to left.
type MMR struct {
	domain string
	count  uint64
	peaks  []mmrPeak
}

type mmrPeak struct {
	height uint8
	hash   Hash
}

func NewMMR(domain string) (*MMR, error) {
	if domain == "" || !utf8.ValidString(domain) || uint64(len(domain)) > math.MaxUint32 {
		return nil, fmt.Errorf("MMR domain must be non-empty UTF-8 fitting uint32")
	}
	return &MMR{domain: domain}, nil
}

func (m *MMR) Append(leaf []byte) error {
	if m == nil || m.domain == "" {
		return fmt.Errorf("MMR must be initialized with NewMMR")
	}
	if m.count == math.MaxUint64 {
		return fmt.Errorf("MMR leaf count overflows uint64")
	}
	node := mmrPeak{hash: m.leaf(m.count, leaf)}
	for len(m.peaks) > 0 && m.peaks[len(m.peaks)-1].height == node.height {
		last := len(m.peaks) - 1
		node.hash = m.node(m.peaks[last].hash, node.hash)
		node.height++
		m.peaks = m.peaks[:last]
	}
	m.peaks = append(m.peaks, node)
	m.count++
	return nil
}

func (m *MMR) LeafCount() uint64 { return m.count }

// Clone returns an independent accumulator at the same prefix.
func (m *MMR) Clone() *MMR {
	if m == nil {
		return nil
	}
	copy := *m
	copy.peaks = append([]mmrPeak(nil), m.peaks...)
	return &copy
}

func (m *MMR) Root() Hash {
	if len(m.peaks) == 0 {
		return HashBytes(m.prefix("TRUEOPEN_MMR_EMPTY_V1"))
	}
	root := m.peaks[len(m.peaks)-1].hash
	for i := len(m.peaks) - 2; i >= 0; i-- {
		root = m.node(m.peaks[i].hash, root)
	}
	return root
}

func (m *MMR) prefix(tag string) []byte {
	out := make([]byte, len(tag)+4+len(m.domain))
	copy(out, tag)
	binary.BigEndian.PutUint32(out[len(tag):], uint32(len(m.domain)))
	copy(out[len(tag)+4:], m.domain)
	return out
}

func (m *MMR) leaf(index uint64, leaf []byte) Hash {
	h := sha256.New()
	h.Write(m.prefix("TRUEOPEN_MMR_LEAF_V1"))
	var sizes [16]byte
	binary.BigEndian.PutUint64(sizes[:8], index)
	binary.BigEndian.PutUint64(sizes[8:], uint64(len(leaf)))
	h.Write(sizes[:])
	h.Write(leaf)
	return Hash(h.Sum(nil))
}

func (m *MMR) node(left, right Hash) Hash {
	h := sha256.New()
	h.Write(m.prefix("TRUEOPEN_MMR_NODE_V1"))
	h.Write(left[:])
	h.Write(right[:])
	return Hash(h.Sum(nil))
}

func MMRRoot(domain string, leaves [][]byte) (Hash, error) {
	mmr, err := NewMMR(domain)
	if err != nil {
		return Hash{}, err
	}
	for _, leaf := range leaves {
		if err := mmr.Append(leaf); err != nil {
			return Hash{}, err
		}
	}
	return mmr.Root(), nil
}

// OutputMMRRoot commits exact ordered TEXT chunks, including their boundaries.
// Empty output is represented by one empty chunk; an empty tree is not output.
func OutputMMRRoot(chunks [][]byte) (Hash, error) {
	if len(chunks) == 0 {
		return Hash{}, fmt.Errorf("output MMR requires at least one chunk; empty output uses one empty chunk")
	}
	nonempty := false
	for i, chunk := range chunks {
		if !utf8.Valid(chunk) {
			return Hash{}, fmt.Errorf("output chunk %d must be valid UTF-8 TEXT", i)
		}
		nonempty = nonempty || len(chunk) > 0
	}
	if !nonempty && len(chunks) != 1 {
		return Hash{}, fmt.Errorf("empty output must have exactly one empty chunk")
	}
	return MMRRoot(DomainOutputMMRV1, chunks)
}

// OutputMMRRootFromLengths replays the exact TEXT boundaries recorded with an
// output artifact. Lengths must cover all bytes and each chunk must be UTF-8.
func OutputMMRRootFromLengths(data []byte, lengths []uint64) (Hash, error) {
	if len(lengths) == 0 {
		return Hash{}, fmt.Errorf("output chunk lengths must be non-empty")
	}
	if len(data) == 0 && (len(lengths) != 1 || lengths[0] != 0) {
		return Hash{}, fmt.Errorf("empty output must have exactly one zero chunk length")
	}
	mmr, err := NewMMR(DomainOutputMMRV1)
	if err != nil {
		return Hash{}, err
	}
	var offset uint64
	for i, length := range lengths {
		if length > uint64(len(data))-offset {
			return Hash{}, fmt.Errorf("output chunk %d length exceeds remaining artifact bytes", i)
		}
		chunk := data[offset : offset+length]
		if !utf8.Valid(chunk) {
			return Hash{}, fmt.Errorf("output chunk %d must be valid UTF-8 TEXT", i)
		}
		if err := mmr.Append(chunk); err != nil {
			return Hash{}, err
		}
		offset += length
	}
	if offset != uint64(len(data)) {
		return Hash{}, fmt.Errorf("output chunk lengths cover %d bytes, artifact has %d", offset, len(data))
	}
	return mmr.Root(), nil
}
