package codec

func OutputHash(canonicalOutputBytes []byte) Hash {
	return HashBytes(canonicalOutputBytes)
}

func CanonicalOutputPackageHash(canonicalPackageBytes []byte) Hash {
	return HashBytes(canonicalPackageBytes)
}
