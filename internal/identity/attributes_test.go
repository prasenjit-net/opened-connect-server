package identity

import (
	"encoding/json"
	"testing"
)

func TestAttributeSnapshotsAreIsolated(t *testing.T) {
	state := fileState{UsersMap: map[string]User{}}
	original := User{Profile: Profile{ID: "one", Email: "one@example.com", Claims: Claims{CustomAttributes: map[string]json.RawMessage{"key": json.RawMessage(`"value"`)}}}}
	if err := state.SaveUser(original); err != nil {
		t.Fatal(err)
	}
	original.CustomAttributes["key"][1] = 'X'
	first, _ := state.User("one")
	if string(first.CustomAttributes["key"]) != `"value"` {
		t.Fatal("SaveUser retained caller's mutable attributes")
	}
	first.CustomAttributes["key"][1] = 'Y'
	second, _ := state.User("one")
	if string(second.CustomAttributes["key"]) != `"value"` {
		t.Fatal("read snapshot mutated stored attributes")
	}
}
