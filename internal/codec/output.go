package codec

func OutputHash(canonicalOutputBytes []byte) Hash {
	return HashBytes(canonicalOutputBytes)
}
