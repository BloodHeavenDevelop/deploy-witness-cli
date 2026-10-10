package report

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/netpath"
)

func TestUploadSendsOnePostWithTheToken(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != uploadPath ||
			r.Header.Get("X-Upload-Token") != "one-time" || string(body) != `{"report":1}` {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"publicToken":"abc"}`))
	}))
	defer server.Close()

	answer, err := Upload(context.Background(), server.URL+"/", "one-time", []byte(`{"report":1}`), "test")
	if err != nil {
		t.Fatal(err)
	}
	if answer != `{"publicToken":"abc"}` || calls.Load() != 1 {
		t.Errorf("answer = %q after %d call(s)", answer, calls.Load())
	}
}

// DW-57: a redirect must not deliver the token or the report to another address.
func TestUploadRefusesRedirects(t *testing.T) {
	var leaked atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Add(1)
	}))
	defer elsewhere.Close()

	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect} {
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, elsewhere.URL+"/collected", status)
		}))

		_, err := Upload(context.Background(), origin.URL, "one-time", []byte("{}"), "test")
		origin.Close()
		if !errors.Is(err, netpath.ErrRedirect) {
			t.Errorf("status %d: error = %v, want a refused redirect", status, err)
		}
	}
	if leaked.Load() != 0 {
		t.Fatalf("the redirect target received %d request(s)", leaked.Load())
	}
}

// DW-57: plain http is refused before any connection for anything but loopback.
func TestUploadRefusesPlainHTTP(t *testing.T) {
	_, err := Upload(context.Background(), "http://deploy-witness.example.com", "one-time", []byte("{}"), "test")
	if err == nil || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("error = %v, want a refusal naming https://", err)
	}
}

func TestUploadEndpoint(t *testing.T) {
	endpoint, err := UploadEndpoint("https://deploy-witness.example.com/base/")
	if err != nil {
		t.Fatal(err)
	}
	if got := endpoint.String(); got != "https://deploy-witness.example.com/base"+uploadPath {
		t.Errorf("endpoint = %q", got)
	}
}
