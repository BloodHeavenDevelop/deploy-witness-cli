package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

// Labels are the requirement side of the domain-collision check, so both spellings
// have to survive the parse.
func TestLabelsInBothSyntaxes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte(`
services:
  mapped:
    image: nginx
    labels:
      traefik.enable: "true"
      traefik.http.routers.shop.rule: Host(`+"`"+`shop.example.com`+"`"+`)
  listed:
    image: nginx
    labels:
      - traefik.http.routers.blog.rule=Host(`+"`"+`blog.example.com`+"`"+`)
      - com.example.flag
  none:
    image: nginx
`), 0o600); err != nil {
		t.Fatal(err)
	}

	manifest, err := Parse(path, nil)
	if err != nil {
		t.Fatal(err)
	}

	byName := map[string]map[string]string{}
	for _, svc := range manifest.Services {
		byName[svc.Name] = svc.Labels
	}

	if got := byName["mapped"]["traefik.http.routers.shop.rule"]; got != "Host(`shop.example.com`)" {
		t.Errorf("mapping form: got %q", got)
	}
	if got := byName["listed"]["traefik.http.routers.blog.rule"]; got != "Host(`blog.example.com`)" {
		t.Errorf("sequence form: got %q", got)
	}
	// A label written without a value is present with an empty one, which is not the
	// same as being absent.
	if _, ok := byName["listed"]["com.example.flag"]; !ok {
		t.Error("a valueless label must still be recorded")
	}
	if byName["none"] != nil {
		t.Errorf("a service with no labels must carry nil, got %+v", byName["none"])
	}
}
