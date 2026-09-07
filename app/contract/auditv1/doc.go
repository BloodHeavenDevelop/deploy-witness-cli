// Package auditv1 is the generated Go for the shared `bloodheaven.audit.v1`
// report contract — the document `--upload` sends.
//
// `report.pb.go` beside this file is a byte-for-byte copy of
// `contracts/gen/go/bloodheaven/audit/v1/report.pb.go` at contracts v0.9.0,
// generated from `proto/bloodheaven/audit/v1/report.proto` in that repository.
// It is copied rather than imported because building this binary must not
// require access to a private repository: somebody who is about to run an
// unfamiliar tool as root on their production host should be able to fetch the
// source and build it, and "first get credentials for an organisation you do
// not belong to" is not an answer.
//
// Copying the *generated* file is not the same mistake as restating the shape
// by hand. The proto remains the single source of truth, the wire format and
// the descriptor's file name are unchanged, and the copy moves as one blob:
// `make sync-shared CONTRACTS=/path/to/contracts` overwrites it, and the diff
// shows exactly what the contract did. When it changes, refresh it in the same
// change as the code that needs the new field, and bump CONTRACTS_VERSION in
// the Makefile so the tree records which release it came from.
//
// Do not edit report.pb.go.
package auditv1
