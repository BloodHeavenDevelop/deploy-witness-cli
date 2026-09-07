package pkgmgr

import (
	"regexp"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
)

type apkManager struct{ base }

func (m *apkManager) Name() string        { return "apk" }
func (m *apkManager) PURLType() string    { return "apk" }
func (m *apkManager) Comparator() Compare { return CompareGeneric }
func (m *apkManager) Ecosystem() string   { return osvEcosystem(m.os) }

// apkNameVersion splits "musl-1.2.4-r2" into name and version. The trailing
// "-rN" build suffix is what makes the split unambiguous — package names contain
// dashes freely, versions do not end in one.
var apkNameVersion = regexp.MustCompile(`^(.+)-([^-]+-r\d+)$`)

func (m *apkManager) Installed() ([]Package, error) {
	out, err := m.runner.Output("apk", "info", "-v")
	if err != nil {
		return nil, err
	}

	arch := m.arch()

	var pkgs []Package
	for _, line := range run.Lines(out) {
		match := apkNameVersion.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		pkgs = append(pkgs, Package{Name: match[1], Version: match[2], Arch: arch})
	}
	return pkgs, nil
}

func (m *apkManager) arch() string {
	out, err := m.runner.Output("apk", "--print-arch")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// Updates compares installed versions against the index already on disk. apk has
// no offline severity metadata, so nothing here is marked as a security update —
// the vulnerability section covers that through OSV instead.
func (m *apkManager) Updates() ([]model.Update, error) {
	// Exits 1 when the list is empty.
	out, _, err := m.runner.OutputAllowExit([]int{1}, "apk", "version", "-l", "<")
	if err != nil {
		return nil, err
	}

	var updates []model.Update
	for _, line := range run.Lines(out) {
		// "busybox-1.36.1-r5 < 1.36.1-r7", preceded by an "Installed:" header.
		if strings.HasPrefix(line, "Installed:") {
			continue
		}
		parts := strings.SplitN(line, "<", 2)
		if len(parts) != 2 {
			continue
		}
		match := apkNameVersion.FindStringSubmatch(strings.TrimSpace(parts[0]))
		if match == nil {
			continue
		}
		updates = append(updates, model.Update{
			Package:   match[1],
			Installed: match[2],
			Available: strings.TrimSpace(parts[1]),
			Severity:  model.SeverityUnknown,
			Source:    "apk version -l <",
		})
	}
	return updates, nil
}

// Advisories reports that Alpine ships no local security database. secdb is
// served over HTTP and is not mirrored into the image, so the offline dataset or
// --online is the only route to CVEs here.
func (m *apkManager) Advisories() ([]model.Vulnerability, error) {
	return nil, run.ErrNotFound
}
