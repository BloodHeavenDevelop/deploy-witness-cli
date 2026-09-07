// Package csv renders a slice of records as CSV, resolving each column from a
// dotted field path.
//
// `csv.go` and `csv_test.go` beside this file are a byte-for-byte copy of
// `utils/csv` at utils v0.9.0. They are copied rather than imported because
// building this binary must not require access to a private repository:
// somebody who is about to run an unfamiliar tool as root on their production
// host should be able to fetch the source and build it, and "first get
// credentials for an organisation you do not belong to" is not an answer. The
// package is a hundred lines of stdlib reflection with no dependencies of its
// own, and it is not a piece of platform infrastructure that services must
// share a version of — nothing here talks to anything else.
//
// `make sync-shared UTILS=/path/to/utils` overwrites both files and shows the
// diff. Do not edit them in place; fix `utils/csv` and copy it down.
package csv
