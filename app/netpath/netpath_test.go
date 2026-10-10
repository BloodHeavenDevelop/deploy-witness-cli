package netpath

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCheckEndpoint(t *testing.T) {
	cases := []struct {
		raw string
		ok  bool
	}{
		{"https://deploy-witness.example.com", true},
		{"https://deploy-witness.example.com:8443/base/", true},
		{"http://localhost:8080", true},
		{"http://127.0.0.1:18752", true},
		{"http://[::1]:8080", true},

		{"http://deploy-witness.example.com", false},
		{"http://localhost.example.com", false},
		{"http://10.0.0.5", false},
		{"ftp://example.com", false},
		{"example.com", false},
		{"https://", false},
		{"https://user:pass@example.com", false},
		{"https://example.com/?x=1", false},
		{"https://example.com/#frag", false},
	}
	for _, tc := range cases {
		_, err := CheckEndpoint("--upload", tc.raw)
		if (err == nil) != tc.ok {
			t.Errorf("CheckEndpoint(%q) error = %v, want ok=%v", tc.raw, err, tc.ok)
		}
	}
}

// A redirect must not carry the request anywhere: the second server is never
// contacted, and the caller gets an error naming where the redirect pointed.
func TestClientRefusesRedirects(t *testing.T) {
	var reached atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
	}))
	defer elsewhere.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/collected", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	request, _ := http.NewRequest(http.MethodPost, origin.URL+"/api", strings.NewReader("report"))
	request.Header.Set("X-Upload-Token", "secret")
	response, err := NewHTTPClient(5 * time.Second).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()

	err = RedirectRefused(response)
	if !errors.Is(err, ErrRedirect) {
		t.Fatalf("RedirectRefused = %v, want ErrRedirect", err)
	}
	if !strings.Contains(err.Error(), elsewhere.URL+"/collected") {
		t.Errorf("the error should name the redirect target: %v", err)
	}
	if reached.Load() != 0 {
		t.Fatal("the redirect target was contacted")
	}
}
