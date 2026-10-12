package chainclient

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	sharedv1 "github.com/TrueOpen/cortex/proto/shared/v1"
)

// restProtoJSON renders a Keeper response as ProtoJSON, except that every bytes
// field wire annotates as REST_BYTES_ENCODING_HASH32_LOWER_HEX becomes 64
// lowercase hex characters instead of base64. model_id is such a field, and
// Cortex carries it as hex text in every snapshot, so the typed projections
// below read it without a second decoder.
//
// This used to be the chain's REST spelling as well. It is not any more: wire
// now writes that annotation as "0x" followed by 64 hex, and the bare form here
// is deliberate rather than stale.
//
// Nothing read here comes from the REST projection -- Keeper is read over ABCI
// protobuf, and this function is both the producer and, through the decoder in
// protojson.go, the only consumer. Respelling it would reach two places that do
// not mention it. The decoder tells hex from base64 by length, so an encoder
// respelled alone stops decoding; and a model id is carried as text straight
// into trueopen.task.open.<model_id>, a subject wire is deliberately NOT
// respelling, so respelling both would have this node subscribe to a subject no
// Builder publishes to. See hash32_text_form_test.go, which fails on either.
func restProtoJSON(message proto.Message) ([]byte, error) {
	encoded, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(message)
	if err != nil {
		return nil, err
	}
	var tree any
	if err := json.Unmarshal(encoded, &tree); err != nil {
		return nil, err
	}
	if err := hexHash32Fields(message.ProtoReflect(), tree); err != nil {
		return nil, err
	}
	return json.Marshal(tree)
}

func hexHash32Fields(message protoreflect.Message, tree any) error {
	object, ok := tree.(map[string]any)
	if !ok {
		return nil
	}
	var walkErr error
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		name := string(field.Name())
		child, present := object[name]
		if !present {
			return true
		}
		switch {
		case field.Kind() == protoreflect.BytesKind && !field.IsList() && !field.IsMap():
			if hash32Annotated(field) {
				raw := value.Bytes()
				if len(raw) != 32 {
					walkErr = fmt.Errorf("%s is annotated Hash32 but carries %d bytes", field.FullName(), len(raw))
					return false
				}
				object[name] = hex.EncodeToString(raw)
			}
		case field.Kind() == protoreflect.MessageKind && field.IsList():
			items, _ := child.([]any)
			list := value.List()
			for i := 0; i < list.Len() && i < len(items); i++ {
				if walkErr = hexHash32Fields(list.Get(i).Message(), items[i]); walkErr != nil {
					return false
				}
			}
		case field.Kind() == protoreflect.MessageKind && !field.IsMap():
			if walkErr = hexHash32Fields(value.Message(), child); walkErr != nil {
				return false
			}
		}
		return true
	})
	return walkErr
}

func hash32Annotated(field protoreflect.FieldDescriptor) bool {
	options := field.Options()
	if options == nil || !proto.HasExtension(options, sharedv1.E_RestBytesEncoding) {
		return false
	}
	return proto.GetExtension(options, sharedv1.E_RestBytesEncoding).(sharedv1.RESTBytesEncoding) == sharedv1.RESTBytesEncoding_REST_BYTES_ENCODING_HASH32_LOWER_HEX
}
