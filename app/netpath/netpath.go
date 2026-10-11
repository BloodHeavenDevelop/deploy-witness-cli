// Package netpath holds the rules every outbound path of this tool follows.
//
// There are exactly three of those paths — --online (the OSV API), --egress (one TCP
// connect per registry) and --upload (one POST of the report) — and each is enabled
// only by a flag typed on the command line. This package is where the parts they
// share live, so that the three cannot each grow a slightly different idea of what
// "an address the operator gave us" may be:
//
//   - An address must be https://. Plain http:// is accepted only for a loopback
//     host (localhost, 127.0.0.0/8, ::1), where nothing crosses a network a third
//     party could watch; that exception exists for a development stack and for tests.
//   - A redirect is never followed. Following one would send the request — a token,
//     a report, a package inventory — to an address the operator never typed. The
//     answer is reported instead, with where it pointed.
//   - The address is printed before anything is sent, together with the proxy the
//     request will go through, if any.
//
// The list of files allowed to touch the network at all is enforced by a test in
// this package (static_test.go), so a fourth path cannot appear without a diff to
// that list.
package netpath

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Paths and the flags that enable them. The names are what network.csv prints.
const (
	PathOSV         = "osv-api"
	PathDistroFeeds = "distro-feeds"
	PathEgress      = "registry-egress"
	PathUpload      = "upload"

	FlagOnline = "--online"
	FlagEgress = "--egress"
	FlagUpload = "--upload"
)

// CheckEndpoint validates a base URL the operator supplied for a network path.
//
// It returns the parsed URL so callers do not parse the same string twice. flag is
// only used to name the offending option in the error.
func CheckEndpoint(flag, raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%s %q is not a URL: %w", flag, raw, err)
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return nil, fmt.Errorf("%s %q has no host; expected https://host[:port]", flag, raw)
	}
	if parsed.User != nil {
		// Credentials in a URL end up in logs, in shell history and in the
		// recipient line this tool prints. The upload is authorised by its token.
		return nil, fmt.Errorf("%s must not carry credentials in the URL", flag)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%s %q must be a base URL without a query or fragment", flag, raw)
	}

	switch strings.ToLower(parsed.Scheme) {
	case "https":
	case "http":
		if !IsLoopbackHost(parsed.Hostname()) {
			return nil, fmt.Errorf("%s %q is plain http: only https:// is accepted "+
				"(http:// only for localhost, 127.0.0.0/8 or ::1)", flag, raw)
		}
	default:
		return nil, fmt.Errorf("%s %q: unsupported scheme %q, expected https://", flag, raw, parsed.Scheme)
	}
	return parsed, nil
}

// IsLoopbackHost reports whether host is the loopback interface by its literal
// name or address. A name that merely resolves to loopback does not count: what it
// resolves to is decided by somebody else's DNS at the moment of the request.
func IsLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ErrRedirect is wrapped by RedirectRefused.
var ErrRedirect = errors.New("redirect refused")

// NewHTTPClient is the client every HTTP path uses: bounded by a timeout, and
// unwilling to follow a redirect. With http.ErrUseLastResponse the 3xx response
// itself is returned to the caller, which turns it into an error via
// RedirectRefused — nothing is re-sent to the new location.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// RedirectRefused turns a 3xx response into an error naming where it pointed, or
// returns nil for any other status.
func RedirectRefused(response *http.Response) error {
	if response.StatusCode < 300 || response.StatusCode >= 400 {
		return nil
	}
	location := response.Header.Get("Location")
	if location == "" {
		location = "(no Location header)"
	}
	return fmt.Errorf("%s answered %s pointing to %s; redirects are not followed, so nothing was "+
		"sent there — give the final address instead: %w",
		response.Request.URL.Redacted(), response.Status, location, ErrRedirect)
}

// ProxyFor names the proxy a request to target would go through, as host:port, or
// "" when it goes direct. Credentials in the proxy URL are never printed.
func ProxyFor(target *url.URL) string {
	if target == nil {
		return ""
	}
	request := &http.Request{URL: target, Header: http.Header{}}
	proxy, err := http.ProxyFromEnvironment(request)
	if err != nil || proxy == nil {
		return ""
	}
	return proxy.Host
}

// Describe renders an endpoint for a log line or network.csv: the URL and, when
// the environment routes it through a proxy, which one.
func Describe(target *url.URL) string {
	if target == nil {
		return ""
	}
	out := target.Redacted()
	if proxy := ProxyFor(target); proxy != "" {
		out += " (via proxy " + proxy + ")"
	}
	return out
}
