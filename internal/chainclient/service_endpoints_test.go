package chainclient

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/cosmos/gogoproto/proto"

	hubv1 "github.com/TrueOpen/cortex/proto/hub/v1"
	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
)

const descriptorTestHash = "1111111111111111111111111111111111111111111111111111111111111111"

func descriptorTestHashBytes() []byte {
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = 0x11
	}
	return hash
}

func descriptorTestHexHash() HexHash {
	var hash HexHash
	copy(hash[:], descriptorTestHashBytes())
	return hash
}

func nexusEndpointWire() *hubv1.ServiceEndpointV1 {
	return &hubv1.ServiceEndpointV1{
		EndpointKind:    hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC,
		Uri:             "grpcs://nexus.builder.example.org:8443",
		ProtocolVersion: "v1",
	}
}

func serviceDescriptorRow(endpoints ...*hubv1.ServiceEndpointV1) *hubv1.ServiceDescriptorState {
	return &hubv1.ServiceDescriptorState{
		ParticipantType:   sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER,
		OperatorAddress:   "trueopen1builder",
		DescriptorVersion: 7,
		EndpointCount:     uint32(len(endpoints)),
		Endpoints:         endpoints,
		DescriptorHash:    descriptorTestHashBytes(),
		UpdatedHeight:     120,
	}
}

func serviceDescriptorResponse() *hubv1.QueryServiceDescriptorResponse {
	return &hubv1.QueryServiceDescriptorResponse{Descriptor_: serviceDescriptorRow(nexusEndpointWire())}
}

// descriptorServer answers Query/ServiceDescriptor with one row so the reader is
// exercised over the real ABCI protobuf path, not a hand-built struct.
func descriptorServer(t *testing.T, row *hubv1.ServiceDescriptorState) *KeeperABCIClient {
	t.Helper()
	server := newABCITestServer(t, func(path, _ string, _ []byte) (proto.Message, uint32, string) {
		if path != hubQuery+"ServiceDescriptor" {
			t.Fatalf("unexpected ABCI path %q", path)
		}
		return &hubv1.QueryServiceDescriptorResponse{Descriptor_: row}, 0, ""
	})
	t.Cleanup(server.Close)
	return NewKeeperABCIClient(server.URL)
}

func readDescriptor(t *testing.T, row *hubv1.ServiceDescriptorState) (ServiceDescriptorSnapshot, error) {
	t.Helper()
	return descriptorServer(t, row).ServiceDescriptor(context.Background(), ParticipantTypeBuilder, "trueopen1builder", 900)
}

// The frozen request selects (participant_type, operator_address) only, and
// participant_type is an enum on that wire, not the pre-freeze string. If the
// enum were sent as a string the keeper would answer for nobody.
//
// The expectation is the request bytes, assembled tag by tag from
// TrueOpen/node d8792e6 proto/hub/v1/query_registry.proto:181-184
// (participant_type = 1 varint, operator_address = 2 string) and from
// proto/hub/v1/common.proto:23 (PARTICIPANT_TYPE_BUILDER = 2). Decoding the
// body with the same hand-written type that produced it would round-trip a wrong
// tag green on both sides, which is the hole PR #182 closed for the Task-facts
// requests; this is the same treatment for this one.
func TestServiceDescriptorRequestCarriesTheParticipantEnum(t *testing.T) {
	var observed []byte
	server := newABCITestServer(t, func(_, _ string, data []byte) (proto.Message, uint32, string) {
		observed = append([]byte(nil), data...)
		return serviceDescriptorResponse(), 0, ""
	})
	defer server.Close()

	if _, err := NewKeeperABCIClient(server.URL).ServiceDescriptor(
		context.Background(), ParticipantTypeBuilder, "trueopen1builder", 900,
	); err != nil {
		t.Fatalf("ServiceDescriptor() error = %v", err)
	}
	want := frozenWire(varintField(1, 2), lenDelimited(2, []byte("trueopen1builder")))
	if !bytes.Equal(observed, want) {
		t.Fatalf("ServiceDescriptor request = %x, want %x", observed, want)
	}
}

func TestServiceDescriptorReadsEveryEndpointByKind(t *testing.T) {
	gateway := &hubv1.ServiceEndpointV1{
		EndpointKind:    hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_OBJECT_GATEWAY_HTTPS,
		Uri:             "https://gateway.builder.example.org",
		ProtocolVersion: "v2",
		TlsPubkeyHash:   descriptorTestHashBytes(),
	}
	descriptor, err := readDescriptor(t, serviceDescriptorRow(nexusEndpointWire(), gateway))
	if err != nil {
		t.Fatalf("ServiceDescriptor() error = %v", err)
	}
	nexus, err := descriptor.Endpoint(EndpointKindNexusGRPC)
	if err != nil {
		t.Fatalf("Endpoint(NEXUS_GRPC) error = %v", err)
	}
	if nexus.URI != "grpcs://nexus.builder.example.org:8443" || nexus.ProtocolVersion != "v1" {
		t.Fatalf("NEXUS_GRPC endpoint = %#v", nexus)
	}
	if nexus.TLSPubkeyHash.Present() {
		t.Fatalf("NEXUS_GRPC tls_pubkey_hash = %s, want absent", nexus.TLSPubkeyHash)
	}
	object, err := descriptor.Endpoint(EndpointKindObjectGatewayHTTPS)
	if err != nil {
		t.Fatalf("Endpoint(OBJECT_GATEWAY_HTTPS) error = %v", err)
	}
	pin, present := object.TLSPubkeyHash.Hash()
	if !present || pin.String() != descriptorTestHash {
		t.Fatalf("OBJECT_GATEWAY_HTTPS pin = %s present = %t", pin, present)
	}
	// A kind the descriptor does not publish is an error, never the neighbouring
	// endpoint and never a zero value.
	if _, err := descriptor.Endpoint(EndpointKindHealthHTTPS); err == nil ||
		!strings.Contains(err.Error(), "publishes no HEALTH_HTTPS endpoint") {
		t.Fatalf("Endpoint(HEALTH_HTTPS) error = %v, want a refusal naming the kind", err)
	}
}

// endpoint_kind is a closed enum. Number 0 is never written by the keeper and
// numbers outside the frozen set do not exist yet; both must refuse the whole
// descriptor rather than be skipped or read as NEXUS_GRPC.
func TestServiceDescriptorRefusesUnknownEndpointKind(t *testing.T) {
	for name, kind := range map[string]hubv1.ServiceEndpointKind{
		"unspecified": hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_UNSPECIFIED,
		"future":      hubv1.ServiceEndpointKind(9),
	} {
		t.Run(name, func(t *testing.T) {
			unknown := nexusEndpointWire()
			unknown.EndpointKind = kind
			_, err := readDescriptor(t, serviceDescriptorRow(unknown))
			if err == nil || !strings.Contains(err.Error(), "is not a kind this build understands") {
				t.Fatalf("err = %v, want a closed-enum refusal", err)
			}
		})
	}
}

// A descriptor that carries an unknown kind alongside a usable NEXUS_GRPC
// endpoint must still be refused: silently ignoring the row Cortex cannot read
// would let a Builder publish a redirect Cortex never notices.
func TestServiceDescriptorRefusesUnknownKindEvenBesideAUsableEndpoint(t *testing.T) {
	unknown := &hubv1.ServiceEndpointV1{
		EndpointKind:    hubv1.ServiceEndpointKind(4),
		Uri:             "https://mystery.builder.example.org",
		ProtocolVersion: "v1",
	}
	_, err := readDescriptor(t, serviceDescriptorRow(nexusEndpointWire(), unknown))
	if err == nil || !strings.Contains(err.Error(), "is not a kind this build understands") {
		t.Fatalf("err = %v, want the whole descriptor refused", err)
	}
}

func TestServiceDescriptorRefusesAnEmptyEndpointList(t *testing.T) {
	_, err := readDescriptor(t, serviceDescriptorRow())
	if err == nil || !strings.Contains(err.Error(), "carries no endpoints") {
		t.Fatalf("err = %v, want an empty endpoint list to be refused", err)
	}
}

// endpoint_count is redundant with the list length, so a disagreement means the
// bytes in hand are not what consensus holds. Neither side may be preferred.
func TestServiceDescriptorRefusesEndpointCountMismatch(t *testing.T) {
	for name, count := range map[string]uint32{"too low": 0, "too high": 2} {
		t.Run(name, func(t *testing.T) {
			row := serviceDescriptorRow(nexusEndpointWire())
			row.EndpointCount = count
			_, err := readDescriptor(t, row)
			if err == nil || !strings.Contains(err.Error(), "endpoint_count") {
				t.Fatalf("err = %v, want an endpoint_count mismatch refusal", err)
			}
		})
	}
}

// The proto documents unique kinds while the keeper's validator only enforces
// strict ascent of (kind, uri, protocol_version), so duplicate kinds are
// reachable on the wire. There is no stated tie-break, so Cortex refuses rather
// than guessing which one is the real Nexus.
func TestServiceDescriptorRefusesDuplicateEndpointKinds(t *testing.T) {
	second := nexusEndpointWire()
	second.Uri = "grpcs://nexus-2.builder.example.org:8443"
	_, err := readDescriptor(t, serviceDescriptorRow(nexusEndpointWire(), second))
	if err == nil || !strings.Contains(err.Error(), "publishes NEXUS_GRPC twice") {
		t.Fatalf("err = %v, want a duplicate-kind refusal", err)
	}
}

func TestServiceDescriptorRefusesEndpointsOutOfKindOrder(t *testing.T) {
	gateway := &hubv1.ServiceEndpointV1{
		EndpointKind:    hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_OBJECT_GATEWAY_HTTPS,
		Uri:             "https://gateway.builder.example.org",
		ProtocolVersion: "v1",
	}
	_, err := readDescriptor(t, serviceDescriptorRow(gateway, nexusEndpointWire()))
	if err == nil || !strings.Contains(err.Error(), "ascending kind order") {
		t.Fatalf("err = %v, want a canonical-order refusal", err)
	}
}

// tls_pubkey_hash is `optional bytes`. Absent, present-and-32-bytes and
// present-and-empty are three different wire states and the reader must not
// collapse any pair of them.
func TestServiceDescriptorDistinguishesAbsentFromPresentTLSPubkeyHash(t *testing.T) {
	absent, err := readDescriptor(t, serviceDescriptorRow(nexusEndpointWire()))
	if err != nil {
		t.Fatalf("absent pin: ServiceDescriptor() error = %v", err)
	}
	absentEndpoint, err := absent.Endpoint(EndpointKindNexusGRPC)
	if err != nil {
		t.Fatalf("absent pin: Endpoint() error = %v", err)
	}
	if absentEndpoint.TLSPubkeyHash.Present() {
		t.Fatalf("absent pin reports Present() = true")
	}
	if got := absentEndpoint.TLSPubkeyHash.String(); got != "absent" {
		t.Fatalf("absent pin renders as %q, want it never to render as a digest", got)
	}
	if _, present := absentEndpoint.TLSPubkeyHash.Hash(); present {
		t.Fatalf("absent pin yields a hash")
	}

	pinned := nexusEndpointWire()
	pinned.TlsPubkeyHash = descriptorTestHashBytes()
	set, err := readDescriptor(t, serviceDescriptorRow(pinned))
	if err != nil {
		t.Fatalf("present pin: ServiceDescriptor() error = %v", err)
	}
	setEndpoint, err := set.Endpoint(EndpointKindNexusGRPC)
	if err != nil {
		t.Fatalf("present pin: Endpoint() error = %v", err)
	}
	hash, present := setEndpoint.TLSPubkeyHash.Hash()
	if !present || hash.String() != descriptorTestHash {
		t.Fatalf("present pin = %s present = %t", hash, present)
	}

	// Present-and-empty is refused rather than silently read as absent: consensus
	// tolerates it, but downstream it would be a claimed pin with no pin in it.
	empty := nexusEndpointWire()
	empty.TlsPubkeyHash = []byte{}
	if _, err := readDescriptor(t, serviceDescriptorRow(empty)); err == nil ||
		!strings.Contains(err.Error(), "present but carries 0 bytes") {
		t.Fatalf("err = %v, want a present-but-empty pin to be refused", err)
	}

	short := nexusEndpointWire()
	short.TlsPubkeyHash = make([]byte, 31)
	if _, err := readDescriptor(t, serviceDescriptorRow(short)); err == nil ||
		!strings.Contains(err.Error(), "present but carries 31 bytes") {
		t.Fatalf("err = %v, want a short pin to be refused", err)
	}

}

func TestServiceDescriptorRefusesUnusableRows(t *testing.T) {
	for name, mutate := range map[string]func(*hubv1.ServiceDescriptorState){
		"zero version": func(r *hubv1.ServiceDescriptorState) { r.DescriptorVersion = 0 },
		"zero updated height": func(r *hubv1.ServiceDescriptorState) {
			r.UpdatedHeight = 0
		},
		"missing hash": func(r *hubv1.ServiceDescriptorState) { r.DescriptorHash = nil },
		"short hash": func(r *hubv1.ServiceDescriptorState) {
			r.DescriptorHash = descriptorTestHashBytes()[:16]
		},
		"zero hash": func(r *hubv1.ServiceDescriptorState) { r.DescriptorHash = make([]byte, 32) },
		"padded operator": func(r *hubv1.ServiceDescriptorState) {
			r.OperatorAddress = " trueopen1builder"
		},
		"unspecified participant": func(r *hubv1.ServiceDescriptorState) {
			r.ParticipantType = sharedv1.ParticipantType_PARTICIPANT_TYPE_UNSPECIFIED
		},
		"missing protocol version": func(r *hubv1.ServiceDescriptorState) {
			r.Endpoints[0].ProtocolVersion = ""
		},
		"empty uri": func(r *hubv1.ServiceDescriptorState) { r.Endpoints[0].Uri = "" },
		"unsupported uri scheme": func(r *hubv1.ServiceDescriptorState) {
			r.Endpoints[0].Uri = "ftp://nexus.builder.example.org"
		},
	} {
		t.Run(name, func(t *testing.T) {
			row := serviceDescriptorRow(nexusEndpointWire())
			mutate(row)
			if _, err := readDescriptor(t, row); err == nil {
				t.Fatalf("err = nil, want %s to be refused", name)
			}
		})
	}
}

func TestServiceDescriptorRejectsResponsesThatDoNotMatchTheQuery(t *testing.T) {
	row := serviceDescriptorRow(nexusEndpointWire())
	row.OperatorAddress = "trueopen1other"
	_, err := readDescriptor(t, row)
	if err == nil || !strings.Contains(err.Error(), "does not match query identity") {
		t.Fatalf("err = %v, want a query identity mismatch", err)
	}
}

func TestServiceDescriptorRejectsUnsupportedParticipantType(t *testing.T) {
	_, err := descriptorServer(t, serviceDescriptorRow(nexusEndpointWire())).
		ServiceDescriptor(context.Background(), "VALIDATOR", "trueopen1builder", 900)
	if err == nil || !strings.Contains(err.Error(), `participant type "VALIDATOR" is unsupported`) {
		t.Fatalf("err = %v, want an unsupported participant type", err)
	}
}

// CurrentAtHeight is the freshness contract that replaced the deleted
// effective_height/expires_height window: the descriptor is fresh iff its
// version is the version the participant's own row calls current, and it was not
// written above the height the read was pinned to.
func TestCurrentAtHeightPinsVersionIdentityAndWriteHeight(t *testing.T) {
	descriptor, err := readDescriptor(t, serviceDescriptorRow(nexusEndpointWire()))
	if err != nil {
		t.Fatalf("ServiceDescriptor() error = %v", err)
	}
	if err := descriptor.CurrentAtHeight(7, 900); err != nil {
		t.Fatalf("CurrentAtHeight(7, 900) = %v, want the current descriptor accepted", err)
	}
	// updated_height may equal the observed height: a descriptor written in the
	// block we read is current, not future-dated.
	if err := descriptor.CurrentAtHeight(7, 120); err != nil {
		t.Fatalf("CurrentAtHeight(7, 120) = %v, want the write height itself accepted", err)
	}
	for name, check := range map[string]func() error{
		"superseded version":   func() error { return descriptor.CurrentAtHeight(8, 900) },
		"unknown current":      func() error { return descriptor.CurrentAtHeight(0, 900) },
		"no observed height":   func() error { return descriptor.CurrentAtHeight(7, 0) },
		"written above height": func() error { return descriptor.CurrentAtHeight(7, 119) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := check(); err == nil {
				t.Fatalf("err = nil, want %s to be refused", name)
			}
		})
	}
}

// A snapshot assembled outside a chain read must obey the same rules, so a
// caller cannot build one the reader would have refused.
func TestNewServiceDescriptorSnapshotAppliesTheReaderRules(t *testing.T) {
	nexus := ServiceEndpointSnapshot{
		Kind: EndpointKindNexusGRPC, URI: "grpcs://nexus.example.org", ProtocolVersion: "v1",
	}
	valid, err := NewServiceDescriptorSnapshot(
		ParticipantTypeBuilder, "trueopen1builder", 7, descriptorTestHexHash(), 120, 1,
		[]ServiceEndpointSnapshot{nexus},
	)
	if err != nil {
		t.Fatalf("NewServiceDescriptorSnapshot() error = %v", err)
	}
	if got := valid.Kinds(); len(got) != 1 || got[0] != EndpointKindNexusGRPC {
		t.Fatalf("Kinds() = %v", got)
	}
	for name, build := range map[string]func() (ServiceDescriptorSnapshot, error){
		"empty list": func() (ServiceDescriptorSnapshot, error) {
			return NewServiceDescriptorSnapshot(ParticipantTypeBuilder, "trueopen1builder", 7, descriptorTestHexHash(), 120, 0, nil)
		},
		"count mismatch": func() (ServiceDescriptorSnapshot, error) {
			return NewServiceDescriptorSnapshot(ParticipantTypeBuilder, "trueopen1builder", 7, descriptorTestHexHash(), 120, 3,
				[]ServiceEndpointSnapshot{nexus})
		},
		"duplicate kind": func() (ServiceDescriptorSnapshot, error) {
			return NewServiceDescriptorSnapshot(ParticipantTypeBuilder, "trueopen1builder", 7, descriptorTestHexHash(), 120, 2,
				[]ServiceEndpointSnapshot{nexus, nexus})
		},
		"unknown kind": func() (ServiceDescriptorSnapshot, error) {
			return NewServiceDescriptorSnapshot(ParticipantTypeBuilder, "trueopen1builder", 7, descriptorTestHexHash(), 120, 1,
				[]ServiceEndpointSnapshot{{Kind: "SOMETHING_ELSE", URI: "https://x", ProtocolVersion: "v1"}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := build(); err == nil {
				t.Fatalf("err = nil, want %s to be refused", name)
			}
		})
	}
}

// TestServiceEndpointURIShapeMatchesTheWritePath pins the four URI-shape rules
// against the upstream line each one comes from.
//
// The asymmetry is the reason they have to be checked here at all. The
// state-invariant validator looks at a scheme prefix and nothing else
// (TrueOpen/node d8792e6 x/hub/types/participant_identity.go:58-65), and
// GenesisState.Validate calls exactly that validator, so a genesis file can seed
// a descriptor row the normal write path would have rejected outright:
// MsgUpdateServiceDescriptor parses the URI and requires a host and forbids
// userinfo, a query and a fragment (d8792e6
// x/hub/keeper/identity_validation.go:202-205). Cortex refuses exactly what
// the chain would never legitimately have accepted, at the boundary where the
// row becomes a snapshot, so the fault is attributable to the row rather than to
// a dial that fails much later.
func TestServiceEndpointURIShapeMatchesTheWritePath(t *testing.T) {
	for name, tc := range map[string]struct {
		uri    string
		wantIn string
	}{
		// identity_validation.go:203 `parsedURI.Host == ""`.
		"no host":           {"https://", "carries no host"},
		"no host with path": {"https:///descriptor", "carries no host"},
		// identity_validation.go:203 `parsedURI.User != nil`.
		"userinfo":          {"https://user@nexus.example.org", "embeds credentials"},
		"userinfo password": {"https://user:pass@nexus.example.org", "embeds credentials"},
		// identity_validation.go:203 `parsedURI.RawQuery != ""`.
		"query": {"https://nexus.example.org?token=abc", "carries a query"},
		// identity_validation.go:203 `parsedURI.Fragment != ""`.
		"fragment": {"https://nexus.example.org#frag", "carries a fragment"},
		// participant_identity.go:62-65 scheme allowlist, restated so the shape
		// rules cannot be read as having replaced it.
		"unsupported scheme": {"ipfs://bafybeigdyrzt", "uses an unsupported scheme"},
		"no scheme":          {"nexus.example.org", "uses an unsupported scheme"},
		// participant_identity.go:58 requireCanonicalNonEmpty.
		"padded": {" https://nexus.example.org", "must be canonical"},
		"empty":  {"", "must be canonical"},
	} {
		t.Run(name, func(t *testing.T) {
			// Refused on both ways into the type: the chain read and the exported
			// constructor share the one gate.
			_, err := NewServiceDescriptorSnapshot(
				ParticipantTypeBuilder, "trueopen1builder", 7, descriptorTestHexHash(), 120, 1,
				[]ServiceEndpointSnapshot{{Kind: EndpointKindNexusGRPC, URI: tc.uri, ProtocolVersion: "v1"}},
			)
			if err == nil || !strings.Contains(err.Error(), tc.wantIn) {
				t.Fatalf("NewServiceDescriptorSnapshot(%q) error = %v, want it to say %q", tc.uri, err, tc.wantIn)
			}
			row := serviceDescriptorRow(nexusEndpointWire())
			row.Endpoints[0].Uri = tc.uri
			if _, err := readDescriptor(t, row); err == nil || !strings.Contains(err.Error(), tc.wantIn) {
				t.Fatalf("ServiceDescriptor(%q) error = %v, want it to say %q", tc.uri, err, tc.wantIn)
			}
		})
	}

	// The write path accepts these, so Cortex must too: a trailing "?" leaves
	// RawQuery empty and a trailing "#" leaves Fragment empty, and both are
	// checked by emptiness upstream (identity_validation.go:203). Refusing them
	// would refuse committed state.
	for _, uri := range []string{
		"https://nexus.example.org", "https://nexus.example.org?", "https://nexus.example.org#",
		"https://nexus.example.org:8443/ingress", "grpcs://nexus.example.org:8443",
		"http://nexus.devnet.invalid:8080",
	} {
		t.Run("accepted/"+uri, func(t *testing.T) {
			if _, err := NewServiceDescriptorSnapshot(
				ParticipantTypeBuilder, "trueopen1builder", 7, descriptorTestHexHash(), 120, 1,
				[]ServiceEndpointSnapshot{{Kind: EndpointKindNexusGRPC, URI: uri, ProtocolVersion: "v1"}},
			); err != nil {
				t.Fatalf("NewServiceDescriptorSnapshot(%q) error = %v, want it accepted", uri, err)
			}
		})
	}
}

// frozenWire builds protobuf bytes by hand so this file's golden vector does not
// depend on the hand-written shim's own marshaler for the field layout. Field
// order is descending, matching what protoc-gen-gogo's MarshalToSizedBuffer
// emits, and repeated field 5 carries its elements in ascending index order.
func frozenWire(fields ...[]byte) []byte {
	var out []byte
	for _, field := range fields {
		out = append(out, field...)
	}
	return out
}

func lenDelimited(fieldNumber byte, payload []byte) []byte {
	out := append([]byte{fieldNumber<<3 | 2}, varint(uint64(len(payload)))...)
	return append(out, payload...)
}

func varintField(fieldNumber byte, value uint64) []byte {
	return append([]byte{fieldNumber << 3}, varint(value)...)
}

func varint(value uint64) []byte {
	var out []byte
	for value >= 0x80 {
		out = append(out, byte(value)|0x80)
		value >>= 7
	}
	return append(out, byte(value))
}

// TestServiceDescriptorDecodesHandBuiltFrozenWire is the golden vector for the
// hand-written shim. It pins every frozen field number and wire type from
// TrueOpen/node d8792e6 proto/hub/v1/participant_identity.proto:23-28,63-71
// and proto/hub/v1/query_registry.proto:186-189 against bytes assembled
// tag by tag, so a wrong field number or wire type in
// proto/hub/v1/service_descriptor_frozen.pb.go fails here rather than
// silently decoding a keeper response into the wrong fields.
//
// It also pins the presence encoding: the second endpoint carries field 4 and
// the first does not, and those are the only two states the shim's `repeated
// bytes` model distinguishes on the wire.
func TestServiceDescriptorDecodesHandBuiltFrozenWire(t *testing.T) {
	// ServiceEndpointV1{NEXUS_GRPC, "https://nexus.example.org", "v1"} with no
	// tls_pubkey_hash: fields 3, 2, 1 descending.
	nexus := frozenWire(
		lenDelimited(3, []byte("v1")),
		lenDelimited(2, []byte("https://nexus.example.org")),
		varintField(1, 1),
	)
	// ServiceEndpointV1{HEALTH_HTTPS, "https://health.example.org", "v2",
	// tls_pubkey_hash present}: fields 4, 3, 2, 1 descending.
	health := frozenWire(
		lenDelimited(4, descriptorTestHashBytes()),
		lenDelimited(3, []byte("v2")),
		lenDelimited(2, []byte("https://health.example.org")),
		varintField(1, 3),
	)
	row := frozenWire(
		varintField(7, 120),
		lenDelimited(6, descriptorTestHashBytes()),
		lenDelimited(5, nexus),
		lenDelimited(5, health),
		varintField(4, 2),
		lenDelimited(2, []byte("trueopen1builder")),
		varintField(3, 7),
		varintField(1, 2),
	)
	wire := lenDelimited(1, row)

	var response hubv1.QueryServiceDescriptorResponse
	if err := unmarshalTestProto(wire, &response); err != nil {
		t.Fatalf("Unmarshal golden wire: %v", err)
	}
	descriptor, err := decodeServiceDescriptor(response.Descriptor_, ParticipantTypeBuilder, "trueopen1builder")
	if err != nil {
		t.Fatalf("decodeServiceDescriptor: %v", err)
	}
	if descriptor.DescriptorVersion != 7 || descriptor.UpdatedHeight != 120 ||
		descriptor.DescriptorHash.String() != descriptorTestHash ||
		descriptor.ParticipantType != ParticipantTypeBuilder ||
		descriptor.OperatorAddress != "trueopen1builder" {
		t.Fatalf("descriptor = %+v", descriptor)
	}
	nexusEndpoint, err := descriptor.Endpoint(EndpointKindNexusGRPC)
	if err != nil {
		t.Fatalf("Endpoint(NEXUS_GRPC): %v", err)
	}
	if nexusEndpoint.URI != "https://nexus.example.org" || nexusEndpoint.ProtocolVersion != "v1" {
		t.Fatalf("NEXUS_GRPC = %+v", nexusEndpoint)
	}
	if nexusEndpoint.TLSPubkeyHash.Present() {
		t.Fatalf("NEXUS_GRPC carried no field 4 on the wire but reports a present pin")
	}
	healthEndpoint, err := descriptor.Endpoint(EndpointKindHealthHTTPS)
	if err != nil {
		t.Fatalf("Endpoint(HEALTH_HTTPS): %v", err)
	}
	if healthEndpoint.URI != "https://health.example.org" || healthEndpoint.ProtocolVersion != "v2" {
		t.Fatalf("HEALTH_HTTPS = %+v", healthEndpoint)
	}
	pin, present := healthEndpoint.TLSPubkeyHash.Hash()
	if !present || pin.String() != descriptorTestHash {
		t.Fatalf("HEALTH_HTTPS pin = %s present = %t", pin, present)
	}
}

// The pre-freeze wire is not a decodable subset of the frozen one, which is why
// the shim exists. participant_type is field 1 of both, a length-delimited
// string pre-freeze and a varint enum frozen, so the frozen decoder must refuse
// the pre-freeze bytes outright rather than read them as something plausible.
