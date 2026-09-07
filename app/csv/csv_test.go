package csv

import (
	"strings"
	"testing"
)

type address struct {
	City string `json:"city"`
}

type person struct {
	Name     string   `json:"name"`
	Age      int      `json:"age"`
	Addr     address  `json:"addr"`
	AddrPtr  *address `json:"addrPtr"`
	Untagged string
}

func TestGenerate_LengthMismatch(t *testing.T) {
	_, err := Generate(nil, []string{"a", "b"}, []string{"A"})
	if err == nil {
		t.Fatal("expected error when paths and headers differ in length")
	}
	if !strings.Contains(err.Error(), "length") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGenerate_HeadersOnly(t *testing.T) {
	out, err := Generate([]any{}, []string{"name"}, []string{"Name"})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out); got != "Name\n" {
		t.Errorf("got %q, want header-only output", got)
	}
}

func TestGenerate_FieldsAndPaths(t *testing.T) {
	data := []any{
		person{
			Name:     "Alice",
			Age:      30,
			Addr:     address{City: "Berlin"},
			AddrPtr:  &address{City: "Paris"},
			Untagged: "u1",
		},
		person{Name: "Bob", Age: 0}, // AddrPtr nil, Addr zero
	}
	paths := []string{"name", "age", "addr.city", "addrPtr.city", "Untagged", "missing"}
	headers := []string{"Name", "Age", "City", "PtrCity", "Untagged", "Missing"}

	out, err := Generate(data, paths, headers)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	want := "Name,Age,City,PtrCity,Untagged,Missing\n" +
		"Alice,30,Berlin,Paris,u1,\n" +
		"Bob,0,,,,\n"
	if got != want {
		t.Errorf("csv mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestGenerate_MapAccess(t *testing.T) {
	data := []any{
		map[string]any{"k": "v1"},
		map[string]any{}, // missing key -> empty cell
	}
	out, err := Generate(data, []string{"k"}, []string{"K"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(out), "K\nv1\n\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGenerate_UntaggedFieldCaseInsensitive(t *testing.T) {
	// A field without a json tag is matched case-insensitively by Go name.
	data := []any{person{Untagged: "hit"}}
	out, err := Generate(data, []string{"untagged"}, []string{"U"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(out), "U\nhit\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
