package modelmanifest

import (
	"strings"
	"testing"
)

func TestValidateURIAcceptsTheAllowedForms(t *testing.T) {
	longPath := "https://models.trueopen.example/m/"
	atLimit := longPath + strings.Repeat("a", DefaultMaxManifestURIBytes-len(longPath))
	for _, uri := range []string{
		"https://models.trueopen.example/manifests/golden-model/v1.json",
		"https://models.trueopen.example",
		"https://cdn.trueopen.example:8443/m/golden.json?rev=3&sig=AbC-_.~",
		"https://xn--bcher-kva.example/m.json",
		"https://93.184.216.34/m.json",
		"https://[2001:db8::1]:443/m.json",
		"https://models.trueopen.example/a%2Fb/%E2%9C%93.json",
		"ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
		"ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/manifests/golden.json",
		atLimit,
	} {
		if err := ValidateURI(uri, DefaultMaxManifestURIBytes); err != nil {
			t.Errorf("%.80s: %v", uri, err)
		}
	}
}

func TestValidateURIRejectsEverythingElse(t *testing.T) {
	overLimit := "https://models.trueopen.example/m/" + strings.Repeat("a", DefaultMaxManifestURIBytes)
	cases := map[string]string{
		"empty":                       "",
		"over max_manifest_uri_bytes": overLimit,
		"http":                        "http://models.trueopen.example/m.json",
		"uppercase scheme":            "HTTPS://models.trueopen.example/m.json",
		"other scheme":                "ftp://models.trueopen.example/m.json",
		"userinfo":                    "https://user:pass@models.trueopen.example/m.json",
		"fragment":                    "https://models.trueopen.example/m.json#top",
		"space":                       "https://models.trueopen.example/m json",
		"control character":           "https://models.trueopen.example/m\tjson",
		"non-ASCII":                   "https://models.trueopen.example/m\xc3\xa9.json",
		"missing host":                "https:///m.json",
		"uppercase host":              "https://Models.TrueOpen.example/m.json",
		"trailing dot":                "https://models.trueopen.example./m.json",
		"single label":                "https://localhost/m.json",
		"leading hyphen":              "https://-bad.example/m.json",
		"all-digit top-level label":   "https://models.123/m.json",
		"IPv4 leading zero":           "https://010.1.1.1/m.json",
		"IPv4 out of range":           "https://256.1.1.1/m.json",
		"IPv4 three octets":           "https://1.2.3/m.json",
		"IPv6 uppercase":              "https://[2001:DB8::1]/m.json",
		"IPv6 uncompressed":           "https://[2001:db8:0:0:0:0:0:1]/m.json",
		"IPv6 zone":                   "https://[fe80::1%25eth0]/m.json",
		"IPv4-mapped IPv6":            "https://[::ffff:1.2.3.4]/m.json",
		"port 0":                      "https://models.trueopen.example:0/m.json",
		"port leading zero":           "https://models.trueopen.example:08443/m.json",
		"port out of range":           "https://models.trueopen.example:65536/m.json",
		"lowercase percent-encoding":  "https://models.trueopen.example/a%2fb",
		"truncated percent-encoding":  "https://models.trueopen.example/a%2",
		"character outside RFC 3986":  "https://models.trueopen.example/a<b>",
		"CIDv0 wrong length":          "ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbd",
		"CIDv0 non-base58":            "ipfs://Qm00000000000000000000000000000000000000000000",
		"uppercase CIDv1":             "ipfs://BAFYBEIGDYRZT5SFP7UDM7HU76UH7Y26NF3EFUYLQABF3OCLGTQY55FBZDI",
		"other multibase":             "ipfs://zafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
		"CIDv1 short multihash":       "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55f",
		"ipfs query":                  "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi?x=1",
		"missing CID":                 "ipfs://",
	}
	for name, uri := range cases {
		if err := ValidateURI(uri, DefaultMaxManifestURIBytes); err == nil {
			t.Errorf("%s: %.80q was accepted", name, uri)
		}
	}
}
