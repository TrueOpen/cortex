package codec

import "testing"

func TestCanonicalJSONDoesNotEscapeHTML(t *testing.T) {
	got, err := CanonicalJSON(map[string]any{"uri": "https://a.example/m?x=1&y=<2>", "a": "\u2028\n"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":"\u2028\n","uri":"https://a.example/m?x=1&y=<2>"}`
	if string(got) != want {
		t.Fatalf("CanonicalJSON = %s, want %s", got, want)
	}
}
