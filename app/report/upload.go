package report

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Uploading is the only thing this tool does that reaches outward with content, and
// the rules it follows are deliberately narrow:
//
//   - It happens only when --upload and --upload-token were both given. There is no
//     default endpoint, no environment default that could be set by an image, and no
//     telemetry.
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

// Upload sends the contract payload to a witness service and returns the public
// URL of the stored report when the service supplies one.
func Upload(ctx context.Context, baseURL, token string, payload []byte, userAgent string) (string, error) {
	endpoint := strings.TrimRight(baseURL, "/") + uploadPath

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

	client := &http.Client{Timeout: uploadTimeout}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("could not reach %s: %w", endpoint, err)
	}
	defer func() { _ = response.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(response.Body, maxErrorBody))

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("%s answered %s: %s",
			endpoint, response.Status, strings.TrimSpace(string(body)))
	}
	return string(body), nil
}
