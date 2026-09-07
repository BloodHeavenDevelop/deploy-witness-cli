package vuln

import (
	"archive/zip"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// OfflineDB is an OSV dataset loaded from disk and indexed by package name.
type OfflineDB struct {
	byPackage map[string][]Entry
	// Scanned is how many records the loader read, Indexed how many it kept.
	// Both are reported so an operator can tell "the dataset does not cover this
	// host" from "the path was wrong".
	Scanned int
	Indexed int
	Sources int
}

// LoadOffline reads an OSV dataset from a file, a .zip export, a .gz file or a
// directory tree, keeping only records that touch one of the installed packages.
//
// Filtering at load time is what makes a full OSV export usable here: the
// complete dataset is several hundred thousand records, and holding all of them
// would cost more memory than the machine being audited can spare.
func LoadOffline(path string, wanted map[string]bool, ecosystem string) (*OfflineDB, error) {
	db := &OfflineDB{byPackage: map[string][]Entry{}}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !isDatasetFile(p) {
				return nil
			}
			db.Sources++
			return db.loadFile(p, wanted, ecosystem)
		})
		if err != nil {
			return db, err
		}
		return db, nil
	}

	db.Sources = 1
	return db, db.loadFile(path, wanted, ecosystem)
}

func isDatasetFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json", ".jsonl", ".ndjson", ".gz", ".zip":
		return true
	}
	return false
}

func (db *OfflineDB) loadFile(path string, wanted map[string]bool, ecosystem string) error {
	ext := strings.ToLower(filepath.Ext(path))

	if ext == ".zip" {
		reader, err := zip.OpenReader(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		defer reader.Close()

		for _, file := range reader.File {
			if file.FileInfo().IsDir() || !isDatasetFile(file.Name) {
				continue
			}
			rc, err := file.Open()
			if err != nil {
				return fmt.Errorf("%s!%s: %w", path, file.Name, err)
			}
			err = db.consume(rc, wanted, ecosystem)
			rc.Close()
			if err != nil {
				return fmt.Errorf("%s!%s: %w", path, file.Name, err)
			}
		}
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var reader io.Reader = f
	if ext == ".gz" {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		defer gz.Close()
		reader = gz
	}

	if err := db.consume(reader, wanted, ecosystem); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// consume decodes a stream that is either a JSON array of records or a sequence
// of JSON objects (newline-delimited or concatenated), which between them cover
// every layout the OSV exports and mirrors ship.
func (db *OfflineDB) consume(r io.Reader, wanted map[string]bool, ecosystem string) error {
	buffered := bufio.NewReaderSize(r, 64*1024)

	first, err := peekFirstToken(buffered)
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(buffered)

	if first == '[' {
		if _, err := decoder.Token(); err != nil { // consume '['
			return err
		}
		for decoder.More() {
			if err := db.decodeOne(decoder, wanted, ecosystem); err != nil {
				return err
			}
		}
		_, err := decoder.Token() // consume ']'
		return err
	}

	for {
		err := db.decodeOne(decoder, wanted, ecosystem)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (db *OfflineDB) decodeOne(decoder *json.Decoder, wanted map[string]bool, ecosystem string) error {
	var entry Entry
	if err := decoder.Decode(&entry); err != nil {
		return err
	}
	db.Scanned++
	db.index(entry, wanted, ecosystem)
	return nil
}

func (db *OfflineDB) index(entry Entry, wanted map[string]bool, ecosystem string) {
	if entry.Withdrawn != "" {
		return
	}

	seen := map[string]bool{}
	for _, affected := range entry.Affected {
		name := strings.ToLower(affected.Package.Name)
		if name == "" || seen[name] {
			continue
		}
		if len(wanted) > 0 && !wanted[name] {
			continue
		}
		if ecosystem != "" && !EcosystemMatches(affected.Package.Ecosystem, ecosystem) {
			continue
		}
		seen[name] = true
		db.byPackage[name] = append(db.byPackage[name], entry)
		db.Indexed++
	}
}

// Lookup returns the records indexed for a package name.
func (db *OfflineDB) Lookup(name string) []Entry {
	if db == nil {
		return nil
	}
	return db.byPackage[strings.ToLower(name)]
}

// peekFirstToken returns the first non-whitespace byte without consuming it.
func peekFirstToken(r *bufio.Reader) (byte, error) {
	for {
		b, err := r.Peek(1)
		if err != nil {
			return 0, err
		}
		switch b[0] {
		case ' ', '\t', '\r', '\n':
			if _, err := r.Discard(1); err != nil {
				return 0, err
			}
		default:
			return b[0], nil
		}
	}
}
