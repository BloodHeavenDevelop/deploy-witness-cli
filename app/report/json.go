package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// The JSON document has two named halves, and the naming is the point.
//
// `upload` is exactly what --upload sends, byte for byte. `audit` is everything else
// this tool found. A client can read the file, see which half would leave their
// machine, and diff it against what actually arrives — which is a good deal more
// convincing than a promise about it.
//
// It also means the two cannot drift: the uploader marshals the same value this file
// wrote, rather than building a second document from the same data.

// Document is the JSON form of a report.
type Document struct {
	// SchemaVersion is the contract version of the `upload` half.
	SchemaVersion string `json:"schemaVersion"`
	// Upload is the shared audit contract — the findings, the collector outcomes, the
	// change list, the rollback plan and the command journal. This is what is sent.
	Upload json.RawMessage `json:"upload"`
	// Audit is everything that stays local: the host inventory, the pending updates
	// and the vulnerability list. It is not sent, because a remote service has no
	// business holding a full software inventory of somebody's production host.
	Audit *model.Report `json:"audit"`
}

// jsonIndent keeps the file readable. A report a client is expected to inspect
// before uploading it has to be inspectable without a formatter.
const jsonIndent = "  "

// Build assembles the JSON document and the contract payload.
//
// The payload is returned alongside so the uploader sends the identical bytes that
// were written to disk.
func Build(r *model.Report) (*Document, []byte, error) {
	contract := Contract(r)

	// protojson rather than encoding/json: the contract's enums must go out as their
	// names (SEVERITY_BLOCKER), which is what the receiving service parses, and
	// encoding/json would render them as integers.
	marshal := protojson.MarshalOptions{Multiline: true, Indent: jsonIndent, UseProtoNames: true}
	payload, err := marshal.Marshal(contract)
	if err != nil {
		return nil, nil, fmt.Errorf("could not render the contract report: %w", err)
	}

	return &Document{
		SchemaVersion: SchemaVersion,
		Upload:        payload,
		Audit:         r,
	}, payload, nil
}

// WriteJSON renders the whole document to a writer and returns the contract payload.
func WriteJSON(w io.Writer, r *model.Report) ([]byte, error) {
	document, payload, err := Build(r)
	if err != nil {
		return nil, err
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", jsonIndent)
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	return payload, nil
}

// WriteJSONFile writes report.json into a directory and returns its path plus the
// contract payload.
func WriteJSONFile(dir string, r *model.Report) (string, []byte, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", nil, err
	}

	document, payload, err := Build(r)
	if err != nil {
		return "", nil, err
	}
	encoded, err := json.MarshalIndent(document, "", jsonIndent)
	if err != nil {
		return "", nil, err
	}

	path := filepath.Join(dir, "report.json")
	// 0600, for the same reason as the CSV files: this names accounts, open ports
	// and unpatched packages, which is a reconnaissance summary of the host.
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		return "", nil, err
	}
	return path, payload, nil
}
