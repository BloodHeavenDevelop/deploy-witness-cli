package report

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/netpath"
)

// Uploading is the only thing this tool does that reaches outward with content, and
// the rules it follows are deliberately narrow:
//
//   - It happens only when --upload was typed and a token was given (--upload-token
//     or AUDIT_UPLOAD_TOKEN). There is no default endpoint, no environment variable
//     that could choose one, and no telemetry.
//   - Only https:// (plain http:// only for a loopback host), and no redirect is
//     followed: a 3xx is reported as a failure naming where it pointed, and neither
//     the token nor the report is sent there.
//   - One request. No retries in the background, no queue, nothing that could send a
//     report minutes after the operator watched the command finish.
//   - It sends the `upload` half of the JSON document and nothing else, so the
//     operator can read the exact bytes before deciding.
//   - The result is reported, not swallowed. A failed upload is printed and changes
//     the exit code; a tool that silently failed to deliver a report is worse than
//     one that never tried.

// uploadPath is the endpoint on the witness service that accepts a level 2 report.
const uploadPath = "/api/public/audit/upload"

// uploadTimeout bounds the single request.
const uploadTimeout = 30 * time.Second

// maxErrorBody bounds how much of a failure response is quoted back. Enough for a
// validation message, not enough for an error page.
const maxErrorBody = 2000

// UploadEndpoint is the full URL a base address uploads to, after the same checks
// Upload applies. main prints it before anything is sent.
func UploadEndpoint(baseURL string) (*url.URL, error) {
	base, err := netpath.CheckEndpoint("--upload", baseURL)
	if err != nil {
		return nil, err
	}
	endpoint := *base
	endpoint.Path = strings.TrimRight(base.Path, "/") + uploadPath
	endpoint.RawPath = ""
	return &endpoint, nil
}

// Upload sends the contract payload to a witness service and returns the service's
// answer — a small JSON document naming the stored report — when it supplies one.
func Upload(ctx context.Context, baseURL, token string, payload []byte, userAgent string) (string, error) {
	target, err := UploadEndpoint(baseURL)
	if err != nil {
		return "", err
	}
	endpoint := target.String()

	ctx, cancel := context.WithTimeout(ctx, uploadTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("could not build the upload request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	// The token goes in a header rather than the URL: a URL ends up in proxy logs and
	// in shell history, and this one authorises writing a report.
	request.Header.Set("X-Upload-Token", token)
	request.Header.Set("User-Agent", userAgent)

	// Never follows a redirect: the request carries the token and the report, and
	// only the address the operator typed may receive them.
	client := netpath.NewHTTPClient(uploadTimeout)
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("could not reach %s: %w", endpoint, err)
	}
	defer func() { _ = response.Body.Close() }()

	if err := netpath.RedirectRefused(response); err != nil {
		return "", err
	}

	body, _ := io.ReadAll(io.LimitReader(response.Body, maxErrorBody))

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("%s answered %s: %s",
			endpoint, response.Status, strings.TrimSpace(string(body)))
	}
	return string(body), nil
}
