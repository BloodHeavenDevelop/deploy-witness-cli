package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/pkgmgr"
)

// OSVClient talks to the OSV API. It is used only when --online is passed; the
// tool is offline by default because querying it discloses the host's full
// package inventory to a third party.
type OSVClient struct {
	BaseURL    string
	HTTP       *http.Client
	MaxLookups int
	UserAgent  string
}

// NewOSVClient builds a client with the run's timeout.
func NewOSVClient(baseURL string, timeout time.Duration, maxLookups int, userAgent string) *OSVClient {
	return &OSVClient{
		BaseURL:    strings.TrimSuffix(baseURL, "/"),
		HTTP:       &http.Client{Timeout: timeout},
		MaxLookups: maxLookups,
		UserAgent:  userAgent,
	}
}

// queryBatchLimit is the API's documented maximum queries per batch request.
const queryBatchLimit = 1000

type osvQuery struct {
	Package osvQueryPackage `json:"package"`
	Version string          `json:"version"`
}

type osvQueryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			Id string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

// Match pairs an advisory with the installed package it was returned for.
type Match struct {
	Package pkgmgr.Package
	Entry   Entry
}

// Query resolves installed packages to advisories in two steps: one batched
// lookup that returns identifiers, then one detail request per unique identifier.
//
// It returns whatever it resolved plus a list of notes describing anything it
// could not — a truncated result set is reported, never silently returned as if
// it were complete.
func (c *OSVClient) Query(ctx context.Context, pkgs []pkgmgr.Package, ecosystem string) ([]Match, []string, error) {
	if ecosystem == "" {
		return nil, []string{"OSV API skipped: this distribution has no OSV ecosystem"}, nil
	}
	if len(pkgs) == 0 {
		return nil, nil, nil
	}

	var notes []string
	// id -> the packages it was returned for.
	hits := map[string][]pkgmgr.Package{}
	var order []string

	for start := 0; start < len(pkgs); start += queryBatchLimit {
		end := min(start+queryBatchLimit, len(pkgs))
		chunk := pkgs[start:end]

		queries := make([]osvQuery, 0, len(chunk))
		for _, p := range chunk {
			queries = append(queries, osvQuery{
				Package: osvQueryPackage{Name: p.Name, Ecosystem: ecosystem},
				Version: p.Version,
			})
		}

		var response osvBatchResponse
		if err := c.post(ctx, "/v1/querybatch", osvBatchRequest{Queries: queries}, &response); err != nil {
			return nil, notes, err
		}

		for i, result := range response.Results {
			if i >= len(chunk) {
				break
			}
			for _, v := range result.Vulns {
				if _, seen := hits[v.Id]; !seen {
					order = append(order, v.Id)
				}
				hits[v.Id] = append(hits[v.Id], chunk[i])
			}
		}
	}

	if c.MaxLookups > 0 && len(order) > c.MaxLookups {
		notes = append(notes, fmt.Sprintf(
			"OSV API returned %d advisories; only the first %d were fetched (--max-osv-lookups)",
			len(order), c.MaxLookups))
		order = order[:c.MaxLookups]
	}

	var matches []Match
	for _, id := range order {
		entry, err := c.vuln(ctx, id)
		if err != nil {
			notes = append(notes, fmt.Sprintf("OSV API: %s could not be fetched: %v", id, err))
			continue
		}
		for _, p := range hits[id] {
			matches = append(matches, Match{Package: p, Entry: entry})
		}
	}
	return matches, notes, nil
}

func (c *OSVClient) post(ctx context.Context, path string, payload, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)

	return c.do(req, out)
}

func (c *OSVClient) vuln(ctx context.Context, id string) (Entry, error) {
	var entry Entry

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return entry, err
	}
	req.Header.Set("User-Agent", c.UserAgent)

	err = c.do(req, &entry)
	return entry, err
}

func (c *OSVClient) do(req *http.Request, out any) error {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Cap the excerpt: an error page is not a payload we want in a log line.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("%s %s: %s: %s", req.Method, req.URL.Path, resp.Status,
			strings.TrimSpace(string(snippet)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
