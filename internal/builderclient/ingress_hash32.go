package builderclient

// The text form of a Hash32 differs between the IngressAPI and this node.
//
// On the IngressAPI a Hash32 carried as a string is "0x" followed by exactly 64
// lowercase hex characters, 66 in all. Inside Cortex the same value stays bare:
// it is a NATS subject component, a store key, and an input to signature
// preimages, none of which wire respelled when it respelled the ingress. So the
// two spellings meet only here, at the messages that cross the boundary, and
// the prefix never reaches anything that hashes or routes on the value.
//
// nexus keeps the mirror image of this file, which is why a request that
// carries the bare spelling is answered NEXUS_DATA_MALFORMED rather than
// misread.

const ingressHash32Prefix = "0x"

// ingressHash32Len is the length of a Hash32 string on the IngressAPI.
const ingressHash32Len = len(ingressHash32Prefix) + 64

// toIngressHash32 writes the IngressAPI spelling of a bare Hash32. An empty
// value stays empty: several of these fields are optional, and turning an
// absent one into a lone prefix would make it look present and malformed.
func ToIngressHash32(bare string) string {
	if bare == "" {
		return ""
	}
	return ingressHash32Prefix + bare
}

// fromIngressHash32 reads the bare Hash32 of an IngressAPI string, reporting
// false for any other spelling. It refuses rather than repairs: this is where
// another implementation's output is met, and a value that is not the one
// agreed spelling is a disagreement to surface, not to guess at.
func FromIngressHash32(value string) (string, bool) {
	if value == "" {
		return "", true
	}
	if len(value) != ingressHash32Len || value[:len(ingressHash32Prefix)] != ingressHash32Prefix {
		return "", false
	}
	for _, c := range value[len(ingressHash32Prefix):] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", false
		}
	}
	return value[len(ingressHash32Prefix):], true
}
