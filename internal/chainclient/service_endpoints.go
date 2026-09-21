package chainclient

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	hubv1 "github.com/SingaXYZ/cortex/proto/hub/v1"
	sharedv1 "github.com/SingaXYZ/cortex/proto/shared/v1"
)

// ServiceEndpointKind is the closed set of descriptor endpoint kinds
// hub.v1.ServiceEndpointKind admits (SingaXYZ/node d8792e6
// proto/hub/v1/participant_identity.proto:11-20). It is a Cortex-side
// string rather than the wire enum so callers outside this package select an
// endpoint by naming a kind, never by importing the vendored proto types and
// never by position in a list.
//
// The set is closed on purpose: decodeServiceEndpointKind refuses
// SERVICE_ENDPOINT_KIND_UNSPECIFIED and every number the frozen enum does not
// define, rather than defaulting to NEXUS_GRPC or skipping the row. A new kind
// upstream is a new constant here plus a decision about what it means.
type ServiceEndpointKind string

const (
	// EndpointKindNexusGRPC is SERVICE_ENDPOINT_KIND_NEXUS_GRPC = 1. The kind
	// constrains no URI scheme, so the transport decision is the caller's.
	EndpointKindNexusGRPC ServiceEndpointKind = "NEXUS_GRPC"
	// EndpointKindObjectGatewayHTTPS is
	// SERVICE_ENDPOINT_KIND_OBJECT_GATEWAY_HTTPS = 2.
	EndpointKindObjectGatewayHTTPS ServiceEndpointKind = "OBJECT_GATEWAY_HTTPS"
	// EndpointKindHealthHTTPS is SERVICE_ENDPOINT_KIND_HEALTH_HTTPS = 3.
	EndpointKindHealthHTTPS ServiceEndpointKind = "HEALTH_HTTPS"
)

// serviceEndpointURISchemes is the scheme allowlist the keeper's own validator
// enforces on every endpoint URI (node d8792e6
// x/hub/types/participant_identity.go:62-65). Consensus admits two
// plaintext schemes; whether Cortex will dial them is a transport policy
// decision this package deliberately does not make.
var serviceEndpointURISchemes = []string{"https://", "grpcs://", "http://", "grpc://"}

// OptionalHash32 is a protobuf `optional bytes` field that consensus constrains
// to a 32-byte digest when it is present (node d8792e6
// x/hub/types/participant_identity.go:70-75).
//
// Absent and present are separate states and this type refuses to flatten them.
// There is no accessor that yields a usable value without also reporting
// presence, because an absent optional pin is not "the zero digest": it is the
// operator declining to commit one, and a consumer that read 32 zero bytes here
// would be verifying against a value nobody published.
//
// Present-and-empty is refused at decode rather than modelled: a present
// tls_pubkey_hash carrying no bytes is a positive claim to have pinned a key
// with no key in it. That leaves exactly two reachable states.
type OptionalHash32 struct {
	present bool
	value   HexHash
}

// NewOptionalHash32 builds a present value. It is exported for tests and for
// callers assembling a snapshot without a chain read.
func NewOptionalHash32(value HexHash) OptionalHash32 {
	return OptionalHash32{present: true, value: value}
}

// Present reports whether the operator committed a value at all.
func (o OptionalHash32) Present() bool { return o.present }

// Hash returns the committed digest and whether one was committed. A caller that
// ignores the second result is claiming a pin the chain does not carry.
func (o OptionalHash32) Hash() (HexHash, bool) { return o.value, o.present }

// String renders the value for diagnostics without ever printing an absent
// value as a hex digest.
func (o OptionalHash32) String() string {
	if !o.present {
		return "absent"
	}
	return o.value.String()
}

// ServiceEndpointSnapshot is one decoded hub.v1.ServiceEndpointV1
// (d8792e6 proto/hub/v1/participant_identity.proto:23-28).
type ServiceEndpointSnapshot struct {
	Kind ServiceEndpointKind
	// URI is the endpoint as the operator published it, byte-for-byte. It is not
	// normalised here: the descriptor_hash consensus committed covers these
	// exact bytes, and a canonicalising rewrite would make a later comparison
	// against the chain view compare something the chain never signed.
	URI string
	// ProtocolVersion is required non-empty by consensus (node d8792e6
	// x/hub/types/participant_identity.go:66-69).
	ProtocolVersion string
	// TLSPubkeyHash is the optional pin. Absent is the devnet norm: nexus
	// terminates no TLS at all, so it has no key to pin.
	TLSPubkeyHash OptionalHash32
}

// ServiceDescriptorSnapshot is the sole current on-chain descriptor row for one
// participant (d8792e6 proto/hub/v1/participant_identity.proto:61-71),
// read through Query/ServiceDescriptor (d8792e6
// proto/hub/v1/query.proto:47).
//
// The endpoint list is on chain. There is no descriptor document, no
// descriptor_uri and nothing to dereference: the frozen contract deleted all
// three and publishes ServiceDescriptorV1.endpoints in consensus state instead.
//
// endpoints is unexported and keyed by kind so that there is no ordered list to
// index: an endpoint can only be selected by naming the kind it is for.
type ServiceDescriptorSnapshot struct {
	ParticipantType   string
	OperatorAddress   string
	DescriptorVersion uint64
	// DescriptorHash is the keeper-derived TRUEOPEN_SERVICE_DESCRIPTOR_V1 digest
	// over the typed endpoint list (node d8792e6
	// x/hub/keeper/msg_server_identity.go:204-213). It is reported, not
	// recomputed: it is derived from the same endpoints this response carried,
	// so it is not an independent commitment the way the retired document hash
	// was, and reproducing it would require Cortex to decode bech32 operator
	// addresses to their account bytes (ruling 17) and reimplement the shared
	// canonical framing for a check that cannot catch a lying node.
	DescriptorHash HexHash
	UpdatedHeight  uint64

	endpoints map[ServiceEndpointKind]ServiceEndpointSnapshot
}

// NewServiceDescriptorSnapshot assembles a validated snapshot from an endpoint
// list. It applies exactly the rules ServiceDescriptor applies to a chain
// response, so a test or a caller building a snapshot by hand cannot construct
// one the reader would have refused.
//
// endpointCount is passed separately rather than derived from len(endpoints)
// because it is the row's own redundant claim about its own length, and the
// whole point of checking it is that the two can disagree.
func NewServiceDescriptorSnapshot(
	participantType, operatorAddress string,
	descriptorVersion uint64,
	descriptorHash HexHash,
	updatedHeight uint64,
	endpointCount uint32,
	endpoints []ServiceEndpointSnapshot,
) (ServiceDescriptorSnapshot, error) {
	if err := requireAscendingEndpointKinds(endpoints); err != nil {
		return ServiceDescriptorSnapshot{}, err
	}
	indexed, err := indexServiceEndpoints(endpoints)
	if err != nil {
		return ServiceDescriptorSnapshot{}, err
	}
	snapshot := ServiceDescriptorSnapshot{
		ParticipantType:   participantType,
		OperatorAddress:   operatorAddress,
		DescriptorVersion: descriptorVersion,
		DescriptorHash:    descriptorHash,
		UpdatedHeight:     updatedHeight,
		endpoints:         indexed,
	}
	if err := snapshot.Validate(endpointCount); err != nil {
		return ServiceDescriptorSnapshot{}, err
	}
	return snapshot, nil
}

// Validate refuses a descriptor row Cortex cannot act on. endpointCount is the
// row's own endpoint_count field; consensus requires it to equal the length of
// the endpoint list (node d8792e6
// x/hub/types/participant_identity.go:47-49), so a disagreement is not
// something to reconcile by preferring one side. It means the bytes in hand are
// not what consensus holds, and the only safe answer is to refuse.
func (s ServiceDescriptorSnapshot) Validate(endpointCount uint32) error {
	for _, field := range []struct{ name, value string }{
		{name: "participant type", value: s.ParticipantType},
		{name: "operator address", value: s.OperatorAddress},
	} {
		if field.value == "" || field.value != strings.TrimSpace(field.value) {
			return fmt.Errorf("Keeper service descriptor %s is required and must be canonical", field.name)
		}
	}
	if s.DescriptorVersion == 0 {
		return fmt.Errorf("Keeper service descriptor version is required")
	}
	if s.UpdatedHeight == 0 {
		return fmt.Errorf("Keeper service descriptor updated height is required")
	}
	if s.DescriptorHash.IsZero() {
		return fmt.Errorf("Keeper service descriptor hash is required")
	}
	if len(s.endpoints) == 0 {
		return fmt.Errorf("Keeper service descriptor %s carries no endpoints", s.OperatorAddress)
	}
	if int(endpointCount) != len(s.endpoints) {
		return fmt.Errorf(
			"Keeper service descriptor %s reports endpoint_count %d but carries %d endpoints",
			s.OperatorAddress, endpointCount, len(s.endpoints),
		)
	}
	return nil
}

// CurrentAtHeight is the freshness contract that replaces the retired
// effective_height/expires_height window.
//
// The frozen row has no validity window: descriptor_uri, schema_version and
// expires_height are gone from the wire and descriptors no longer expire, they
// are replaced. What "fresh" means now is version identity against the
// participant's own primary row read at the same pinned height: the descriptor
// is current iff its descriptor_version equals the current_descriptor_version
// that row names (d8792e6 proto/hub/v1/builder.proto:48). That is strictly
// stronger than the old window for the property that mattered, because a
// superseded descriptor was previously only rejected once its window elapsed.
//
// updated_height must also be at or below the height the read was pinned to. A
// row claiming a write in the future of the height we asked for is the same
// class of failure as an endpoint_count mismatch.
func (s ServiceDescriptorSnapshot) CurrentAtHeight(currentDescriptorVersion, height uint64) error {
	if height == 0 {
		return fmt.Errorf("service descriptor freshness requires an observed height")
	}
	if currentDescriptorVersion == 0 {
		return fmt.Errorf("service descriptor freshness requires the participant's current descriptor version")
	}
	if s.DescriptorVersion != currentDescriptorVersion {
		return fmt.Errorf(
			"service descriptor version %d is not the current version %d at height %d",
			s.DescriptorVersion, currentDescriptorVersion, height,
		)
	}
	if s.UpdatedHeight > height {
		return fmt.Errorf(
			"service descriptor %d reports updated height %d above the observed height %d",
			s.DescriptorVersion, s.UpdatedHeight, height,
		)
	}
	return nil
}

// Endpoint returns the endpoint published for one kind. A kind the descriptor
// does not carry is an error naming the kind and what the descriptor does
// carry, never a zero endpoint and never a neighbouring kind.
func (s ServiceDescriptorSnapshot) Endpoint(kind ServiceEndpointKind) (ServiceEndpointSnapshot, error) {
	endpoint, ok := s.endpoints[kind]
	if !ok {
		return ServiceEndpointSnapshot{}, fmt.Errorf(
			"service descriptor %d for %s publishes no %s endpoint (it publishes %s)",
			s.DescriptorVersion, s.OperatorAddress, kind, strings.Join(s.KindStrings(), ", "),
		)
	}
	return endpoint, nil
}

// Kinds reports the published kinds in ascending wire order, for diagnostics.
func (s ServiceDescriptorSnapshot) Kinds() []ServiceEndpointKind {
	kinds := make([]ServiceEndpointKind, 0, len(s.endpoints))
	for kind := range s.endpoints {
		kinds = append(kinds, kind)
	}
	sort.Slice(kinds, func(i, j int) bool {
		return serviceEndpointKindOrder[kinds[i]] < serviceEndpointKindOrder[kinds[j]]
	})
	return kinds
}

// KindStrings is Kinds rendered for an error message.
func (s ServiceDescriptorSnapshot) KindStrings() []string {
	kinds := s.Kinds()
	if len(kinds) == 0 {
		return []string{"nothing"}
	}
	names := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		names = append(names, string(kind))
	}
	return names
}

// ServiceDescriptor reads the one current descriptor row for a participant.
//
// The request selects only (participant_type, operator_address): the frozen
// Query/ServiceDescriptor takes no descriptor_version, because the keeper keeps
// exactly one current row per participant and retains no history (d8792e6
// proto/hub/v1/query_registry.proto:181-184,
// proto/hub/v1/participant_identity.proto:61-62). Freshness is therefore
// checked after the read, with CurrentAtHeight.
//
// snapshotHeight 0 reads the latest committed state; a non-zero height pins the
// read and MUST have come from CommittedHeight.
//
// The response is read as typed protobuf rather than through the jsonpb
// projection the older snapshot readers use. The frozen row carries an enum and
// a proto3 optional, and neither survives a jsonpb round trip through a
// hand-written binding that registers no descriptor: the enum would render as a
// bare number and the optional's presence would be indistinguishable from an
// empty value. TaskReceiptFacts already reads identity fields straight off the
// typed frozen response for the same reason.
func (c *KeeperABCIClient) ServiceDescriptor(ctx context.Context, participantType, operatorAddress string, snapshotHeight uint64) (ServiceDescriptorSnapshot, error) {
	participant := strings.ToUpper(strings.TrimSpace(participantType))
	if operatorAddress == "" || operatorAddress != strings.TrimSpace(operatorAddress) {
		return ServiceDescriptorSnapshot{}, fmt.Errorf("service descriptor operator is required and must be canonical")
	}
	wireParticipant, err := encodeParticipantType(participant)
	if err != nil {
		return ServiceDescriptorSnapshot{}, err
	}
	var response hubv1.QueryServiceDescriptorResponse
	request := &hubv1.QueryServiceDescriptorRequest{
		ParticipantType: wireParticipant,
		OperatorAddress: operatorAddress,
	}
	if _, err := c.queryServed(ctx, hubQuery+"ServiceDescriptor", snapshotHeight, request, &response); err != nil {
		return ServiceDescriptorSnapshot{}, err
	}
	return decodeServiceDescriptor(response.Descriptor_, participant, operatorAddress)
}

func decodeServiceDescriptor(row *hubv1.ServiceDescriptorState, participant, operatorAddress string) (ServiceDescriptorSnapshot, error) {
	decodedParticipant, err := decodeParticipantType(row.ParticipantType)
	if err != nil {
		return ServiceDescriptorSnapshot{}, err
	}
	endpoints := make([]ServiceEndpointSnapshot, 0, len(row.Endpoints))
	for index := range row.Endpoints {
		endpoint, err := decodeServiceEndpoint(row.Endpoints[index])
		if err != nil {
			return ServiceDescriptorSnapshot{}, fmt.Errorf("Keeper service descriptor endpoint %d: %w", index, err)
		}
		endpoints = append(endpoints, endpoint)
	}
	var hash HexHash
	if len(row.DescriptorHash) != len(hash) {
		return ServiceDescriptorSnapshot{}, fmt.Errorf(
			"Keeper service descriptor hash must be exactly %d bytes, got %d", len(hash), len(row.DescriptorHash),
		)
	}
	copy(hash[:], row.DescriptorHash)
	// row.EndpointCount is the row's own redundant claim about its endpoint
	// list; NewServiceDescriptorSnapshot refuses a disagreement rather than
	// preferring either side.
	snapshot, err := NewServiceDescriptorSnapshot(
		decodedParticipant, row.OperatorAddress, row.DescriptorVersion, hash, row.UpdatedHeight,
		row.EndpointCount, endpoints,
	)
	if err != nil {
		return ServiceDescriptorSnapshot{}, err
	}
	if snapshot.ParticipantType != participant || snapshot.OperatorAddress != operatorAddress {
		return ServiceDescriptorSnapshot{}, fmt.Errorf("Keeper service descriptor response does not match query identity")
	}
	return snapshot, nil
}

func decodeServiceEndpoint(wire *hubv1.ServiceEndpointV1) (ServiceEndpointSnapshot, error) {
	kind, err := decodeServiceEndpointKind(wire.EndpointKind)
	if err != nil {
		return ServiceEndpointSnapshot{}, err
	}
	// The URI itself is validated by requireServiceEndpointURI, at the one
	// chokepoint every snapshot passes through. Doing it here as well would put
	// the same rule on only one of the two ways into the type.
	if wire.ProtocolVersion == "" || wire.ProtocolVersion != strings.TrimSpace(wire.ProtocolVersion) {
		return ServiceEndpointSnapshot{}, fmt.Errorf("%s protocol_version is required and must be canonical", kind)
	}
	pin, err := decodeOptionalHash32(wire.TlsPubkeyHash, kind)
	if err != nil {
		return ServiceEndpointSnapshot{}, err
	}
	return ServiceEndpointSnapshot{
		Kind:            kind,
		URI:             wire.Uri,
		ProtocolVersion: wire.ProtocolVersion,
		TLSPubkeyHash:   pin,
	}, nil
}

// decodeOptionalHash32 preserves proto3 optional presence, including empty bytes.
func decodeOptionalHash32(wire []byte, kind ServiceEndpointKind) (OptionalHash32, error) {
	if wire == nil {
		return OptionalHash32{}, nil
	}
	if len(wire) != 32 {
		return OptionalHash32{}, fmt.Errorf("%s tls_pubkey_hash is present but carries %d bytes, not 32", kind, len(wire))
	}
	var hash HexHash
	copy(hash[:], wire)
	return NewOptionalHash32(hash), nil
}

func decodeServiceEndpointKind(wire hubv1.ServiceEndpointKind) (ServiceEndpointKind, error) {
	switch wire {
	case hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC:
		return EndpointKindNexusGRPC, nil
	case hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_OBJECT_GATEWAY_HTTPS:
		return EndpointKindObjectGatewayHTTPS, nil
	case hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_HEALTH_HTTPS:
		return EndpointKindHealthHTTPS, nil
	default:
		return "", fmt.Errorf("endpoint_kind %s is not a kind this build understands", wire)
	}
}

// serviceEndpointKindOrder is the wire number of each kind, used to hold a
// decoded descriptor to the canonical ascending order consensus writes.
var serviceEndpointKindOrder = map[ServiceEndpointKind]int32{
	EndpointKindNexusGRPC:          int32(hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC),
	EndpointKindObjectGatewayHTTPS: int32(hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_OBJECT_GATEWAY_HTTPS),
	EndpointKindHealthHTTPS:        int32(hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_HEALTH_HTTPS),
}

// requireAscendingEndpointKinds enforces one kind per descriptor, in ascending
// kind order. That is the write path's own rule, restated on the read side.
//
// MsgUpdateServiceDescriptor rejects a repeated kind outright — "descriptor
// endpoint_kind must be unique" (node d8792e6
// x/hub/keeper/identity_validation.go:196-197) — and requires strict ascent
// by (endpoint_kind, uri) (`:193-195`). The state-invariant validator is looser:
// it only checks strict ascent of the triple (kind, uri, protocol_version)
// (d8792e6 x/hub/types/participant_identity.go:76-80), so a genesis-seeded
// row could hold two endpoints of one kind. Cortex refuses that rather than
// choosing between them: the write path forbids it, there is no stated
// tie-break, and picking the first, the last or the most secure would each be a
// guess dressed up as a rule.
//
// Ascent is checked because it is a canonicalisation invariant descriptor_hash
// depends on, so a list that arrives reordered is refused for the same reason an
// endpoint_count mismatch is.
func requireAscendingEndpointKinds(endpoints []ServiceEndpointSnapshot) error {
	for index := 1; index < len(endpoints); index++ {
		previous := serviceEndpointKindOrder[endpoints[index-1].Kind]
		current := serviceEndpointKindOrder[endpoints[index].Kind]
		if previous == current {
			return fmt.Errorf(
				"service descriptor publishes %s twice; endpoint kinds must be unique", endpoints[index].Kind,
			)
		}
		if previous > current {
			return fmt.Errorf(
				"service descriptor endpoints are not in ascending kind order (%s before %s)",
				endpoints[index-1].Kind, endpoints[index].Kind,
			)
		}
	}
	return nil
}

// indexServiceEndpoints keys the list by kind and is the single gate every
// ServiceDescriptorSnapshot passes through, whether it came off the wire or was
// assembled by a caller. The kind and duplicate checks are restated here rather
// than left to the decoder for exactly that reason, and the URI rules live here
// for the same one: a hand-built snapshot must not be able to carry an endpoint
// the reader would have refused.
func indexServiceEndpoints(endpoints []ServiceEndpointSnapshot) (map[ServiceEndpointKind]ServiceEndpointSnapshot, error) {
	indexed := make(map[ServiceEndpointKind]ServiceEndpointSnapshot, len(endpoints))
	for _, endpoint := range endpoints {
		if _, known := serviceEndpointKindOrder[endpoint.Kind]; !known {
			return nil, fmt.Errorf("endpoint kind %q is not a kind this build understands", endpoint.Kind)
		}
		if _, duplicate := indexed[endpoint.Kind]; duplicate {
			return nil, fmt.Errorf("service descriptor publishes %s twice; endpoint kinds must be unique", endpoint.Kind)
		}
		if err := requireServiceEndpointURI(endpoint.Kind, endpoint.URI); err != nil {
			return nil, err
		}
		indexed[endpoint.Kind] = endpoint
	}
	return indexed, nil
}

// requireServiceEndpointURI is every rule Cortex holds a published endpoint URI
// to. It is one function at one call site because the shape of a URI is a fact
// about the row, not a transport policy: builderdirectory decides whether Cortex
// will DIAL a given scheme, and deliberately does not restate any of this.
//
// The scheme allowlist is the state-invariant validator's, which admits http,
// https, grpc and grpcs (node d8792e6
// x/hub/types/participant_identity.go:62-65), and not the write path's
// https-only rule: a genesis-seeded row can legitimately hold a plaintext
// endpoint, and refusing it at decode would make that state unreadable rather
// than refusable by policy.
//
// The remaining four rules ARE the write path's, because nothing else about the
// URI's shape is reachable through genesis in a form Cortex could act on. The
// state validator checks only a scheme prefix, while
// MsgUpdateServiceDescriptor parses the URI and requires a host and forbids
// userinfo, a query and a fragment (d8792e6
// x/hub/keeper/identity_validation.go:202-205, "descriptor endpoint %d uri
// must be credential-free HTTPS without query or fragment"). So a row carrying
// any of those four could only have arrived through a genesis file, and the
// authoritative directory must not hand a caller back an identity the chain
// would never legitimately have accepted - the Connect client refuses it later
// (internal/builderclient/taskdata_connect.go), and a refusal that far from the
// fact that caused it is a refusal nobody can attribute.
func requireServiceEndpointURI(kind ServiceEndpointKind, uri string) error {
	if uri == "" || uri != strings.TrimSpace(uri) {
		return fmt.Errorf("%s uri is required and must be canonical", kind)
	}
	supported := false
	for _, scheme := range serviceEndpointURISchemes {
		if strings.HasPrefix(uri, scheme) {
			supported = true
			break
		}
	}
	if !supported {
		return fmt.Errorf("%s uri %q uses an unsupported scheme", kind, uri)
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("%s uri %q is not a parseable URL: %w", kind, uri, err)
	}
	// Each clause is one of the write path's four, kept separate so the refusal
	// names the shape that was wrong instead of restating the whole rule.
	switch {
	case parsed.Host == "":
		return fmt.Errorf("%s uri %q carries no host", kind, uri)
	case parsed.User != nil:
		return fmt.Errorf("%s uri %q embeds credentials", kind, uri)
	case parsed.RawQuery != "":
		return fmt.Errorf("%s uri %q carries a query", kind, uri)
	case parsed.Fragment != "":
		return fmt.Errorf("%s uri %q carries a fragment", kind, uri)
	}
	return nil
}

// encodeParticipantType maps Cortex's participant strings onto the frozen
// hub.v1.ParticipantType enum (d8792e6
// proto/hub/v1/common.proto:17-23). The pre-freeze query carried this
// discriminator as a string; the frozen one carries the enum, so the mapping is
// explicit and total rather than a cast.
func encodeParticipantType(participant string) (sharedv1.ParticipantType, error) {
	switch participant {
	case ParticipantTypeBuilder:
		return sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, nil
	case ParticipantTypeCortexNode:
		return sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX, nil
	default:
		return sharedv1.ParticipantType_PARTICIPANT_TYPE_UNSPECIFIED,
			fmt.Errorf("participant type %q is unsupported", participant)
	}
}

func decodeParticipantType(wire sharedv1.ParticipantType) (string, error) {
	switch wire {
	case sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER:
		return ParticipantTypeBuilder, nil
	case sharedv1.ParticipantType_PARTICIPANT_TYPE_CORTEX:
		return ParticipantTypeCortexNode, nil
	default:
		return "", fmt.Errorf("Keeper service descriptor participant_type %s is unsupported", wire)
	}
}
