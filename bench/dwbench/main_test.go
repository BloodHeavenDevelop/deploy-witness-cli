package main

import (
	"strings"
	"testing"
)

func TestDiffLinesFindsWhatTheAuditChanged(t *testing.T) {
	before := "web|running|alpine\n---\ndata\n"
	after := "web|exited|alpine\n---\ndata\nnew-volume\n"
	got := strings.Join(diffLines(before, after), "; ")
	for _, want := range []string{"appeared: web|exited|alpine", "disappeared: web|running|alpine", "appeared: new-volume"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if len(diffLines(before, before)) != 0 {
		t.Error("identical snapshots differ")
	}
}

func TestShellJoinQuotes(t *testing.T) {
	if got := shellJoin([]string{"a b", "it's"}); got != `'a b' 'it'\''s'` {
		t.Errorf("shellJoin = %s", got)
	}
}
