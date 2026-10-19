package witness

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// The bind mount checks beyond "is this a sensitive host path": does the source
// exist on this host, what is it, would the engine create it, can it be written,
// and could the container's user reach it. Each answer is separated from what the
// audit cannot see: a stat shows what the account running the audit sees, and the
// container's user is seen through user namespaces, rootless engines, ACLs and
// SELinux labels this tool does not read — so access is never claimed proven, and
// mode bits that deny it make an unknown, not a problem.

func bindSource(in Input, path string) (model.PathInfo, bool) {
	for _, p := range in.Caps.BindSources {
		if p.Path == path {
			return p, true
		}
	}
	return model.PathInfo{}, false
}

// bindSourceFindings checks one bind mount against what the host showed.
func bindSourceFindings(in Input, svc model.ManifestService, mount model.VolumeMount) []model.Finding {
	info, ok := bindSource(in, mount.Source)
	if !ok {
		return nil
	}
	declared := mount.Source
	if mount.Declared != "" {
		declared = mount.Declared + " (" + mount.Source + ")"
	}
	finding := func(outcome model.Outcome, severity model.FindingSeverity, title, description, why, todo string) model.Finding {
		return model.Finding{
			Code:         "witness.bind_path_conflict",
			Category:     model.CategoryMissing,
			Subject:      mount.Source,
			Severity:     severity,
			Confidence:   model.ConfidenceHigh,
			Outcome:      outcome,
			SortOrder:    2,
			Title:        title,
			Description:  description,
			WhyItMatters: why,
			WhatToDo:     todo,
			Evidence: []model.Evidence{
				manifestEvidence(in, svc.Name, fmt.Sprintf("volumes: %s:%s%s%s", declared, mount.Target,
					readOnlySuffix(mount), createSuffix(mount))),
				evidence(in, "stat "+mount.Source, describePath(info)),
			},
		}
	}

	switch {
	case info.State == "unknown":
		return []model.Finding{finding(model.OutcomeUnknown, model.FindingWarning,
			fmt.Sprintf("Bind source %s could not be examined", mount.Source),
			fmt.Sprintf("Service %q bind-mounts %s, and this account could not stat it: %s.", svc.Name, mount.Source, info.Error),
			"Whether it exists, and what it is, is unknown — not absent.",
			"Re-run the audit as the account that deploys (or root), or check the path by hand.")}

	case info.State == "missing" && mount.CreateHostPath != nil && !*mount.CreateHostPath:
		f := finding(model.OutcomeProblem, model.FindingBlocker,
			fmt.Sprintf("Bind source %s does not exist, and the engine will not create it", mount.Source),
			fmt.Sprintf("Service %q bind-mounts %s with create_host_path: false, and the path does not exist on this host.",
				svc.Name, mount.Source),
			"The container is not created: the engine refuses a bind mount whose source is missing when it is told "+
				"not to create it.",
			fmt.Sprintf("Create %s before deploying, or allow the engine to create it.", mount.Source))
		return []model.Finding{f}

	case info.State == "missing" && mount.CreateHostPath == nil:
		return []model.Finding{finding(model.OutcomeUnknown, model.FindingWarning,
			fmt.Sprintf("Bind source %s does not exist, and whether the engine creates it is not established", mount.Source),
			fmt.Sprintf("Service %q bind-mounts %s in the long syntax without create_host_path, and the path does not "+
				"exist. Whether the engine then creates it depends on the Compose version (5.x creates it; older "+
				"versions refuse), and Compose did not resolve this plan here.", svc.Name, mount.Source),
			"Either the container is not created, or it starts with an empty directory owned by root.",
			fmt.Sprintf("Create %s before deploying, or set create_host_path explicitly.", mount.Source))}

	case info.State == "missing" && filepath.Ext(mount.Source) != "":
		return []model.Finding{finding(model.OutcomeUnknown, model.FindingWarning,
			fmt.Sprintf("Bind source %s does not exist and will be created as a directory", mount.Source),
			fmt.Sprintf("Service %q bind-mounts %s at %s, and the path does not exist. The engine creates a missing "+
				"source as an empty directory owned by root — and the name looks like a file.", svc.Name,
				mount.Source, mount.Target),
			"If the container expects a file there it fails to start (\"not a directory\"), or reads an empty "+
				"directory instead of its configuration. Whether it expects a file cannot be seen from the plan.",
			fmt.Sprintf("Put the file at %s before deploying.", mount.Source))}

	case info.State == "missing":
		// The engine creates it, as an empty directory owned by root: a planned
		// change (changes.csv), not a conflict.
		return nil

	case info.Dangling:
		return []model.Finding{finding(model.OutcomeUnknown, model.FindingWarning,
			fmt.Sprintf("Bind source %s is a symlink to a path that does not exist", mount.Source),
			fmt.Sprintf("Service %q bind-mounts %s, a symlink to %s, which does not exist.", svc.Name, mount.Source,
				info.SymlinkTarget),
			"The engine follows the link; what it does with a dangling one depends on the engine and its version.",
			fmt.Sprintf("Create %s, or point the mount at the real path.", info.SymlinkTarget))}

	case info.ReadOnlyFS && !mount.ReadOnly:
		return []model.Finding{finding(model.OutcomeProblem, model.FindingWarning,
			fmt.Sprintf("Bind source %s is on a read-only filesystem but mounted read/write", mount.Source),
			fmt.Sprintf("Service %q mounts %s read/write, and the filesystem holding it is mounted read-only on "+
				"this host.", svc.Name, mount.Source),
			"The container starts, and every write it makes there fails.",
			fmt.Sprintf("Mount it with :ro if the service only reads it, or move %s to a writable filesystem.", mount.Source))}
	}

	user, who := containerUser(in, svc)
	if uid, gid, numeric := numericUser(user); numeric && info.UID >= 0 {
		if denied := deniedByMode(info, uid, gid, !mount.ReadOnly); denied != "" {
			return []model.Finding{finding(model.OutcomeUnknown, model.FindingWarning,
				fmt.Sprintf("The container user may not be able to %s %s", denied, mount.Source),
				fmt.Sprintf("Service %q runs as %s (%s), and %s is owned by %d:%d with mode %s, which by its mode "+
					"bits does not let that user %s it.", svc.Name, user, who, mount.Source, info.UID, info.GID,
					info.Mode, denied),
				"If the mode bits are the whole story the service fails on its first access. They may not be: ACLs, "+
					"user-namespace remapping, a rootless engine and SELinux labels are not read by this audit.",
				fmt.Sprintf("chown or chmod %s for uid %d before deploying, or check by hand as that user.", mount.Source, uid))}
		}
	}
	return nil
}

func createSuffix(mount model.VolumeMount) string {
	if mount.CreateHostPath != nil && !*mount.CreateHostPath {
		return " (create_host_path: false)"
	}
	return ""
}

func describePath(info model.PathInfo) string {
	switch info.State {
	case "missing":
		return "no such file or directory"
	case "unknown":
		return "could not be examined: " + info.Error
	}
	out := fmt.Sprintf("%s, mode %s, owner %d:%d", info.Type, orUnknown(info.Mode), info.UID, info.GID)
	if info.SymlinkTarget != "" {
		out += ", symlink to " + info.SymlinkTarget
	}
	if info.Dangling {
		out += " (dangling)"
	}
	if info.ReadOnlyFS {
		out += ", on a read-only filesystem"
	}
	return out
}

// containerUser is who the container runs as: the service's `user:`, else the
// image's default user when the image is on the host, else unknown.
func containerUser(in Input, svc model.ManifestService) (user, source string) {
	if svc.User != "" {
		return svc.User, "user: in the plan"
	}
	for _, image := range in.Caps.Images {
		if image.Reference == svc.Image.Raw && svc.Image.Raw != "" {
			if image.User == "" {
				return "0", "the image's default, root"
			}
			return image.User, "the image's default user"
		}
	}
	return "", "unknown — the image is not on this host and the plan sets no user:"
}

// numericUser reads a `uid[:gid]` user. A name cannot be mapped to a uid without
// the image's /etc/passwd, which is not read.
func numericUser(user string) (int, int, bool) {
	if user == "" {
		return 0, 0, false
	}
	name, group, hasGroup := strings.Cut(user, ":")
	uid, err := strconv.Atoi(name)
	if err != nil {
		return 0, 0, false
	}
	gid := -1
	if hasGroup {
		if g, err := strconv.Atoi(group); err == nil {
			gid = g
		}
	}
	return uid, gid, true
}

// deniedByMode says which access the mode bits refuse a uid ("read", "write",
// "enter"), or "". Root is not refused by mode bits.
func deniedByMode(info model.PathInfo, uid, gid int, write bool) string {
	if uid == 0 {
		return ""
	}
	mode, err := strconv.ParseUint(info.Mode, 8, 32)
	if err != nil {
		return ""
	}
	shift := uint(0)
	switch {
	case uid == info.UID:
		shift = 6
	case gid >= 0 && gid == info.GID:
		shift = 3
	}
	bits := (mode >> shift) & 7
	switch {
	case bits&4 == 0:
		return "read"
	case write && bits&2 == 0:
		return "write"
	case info.Type == "directory" && bits&1 == 0:
		return "enter"
	}
	return ""
}

// bindChange is the change-list detail for one bind mount: what the host shows and
// what the deployment does to it.
func bindChange(in Input, svc model.ManifestService, mount model.VolumeMount) string {
	access := "read/write"
	if mount.ReadOnly {
		access = "read only"
	}
	detail := fmt.Sprintf("bind-mounted into %s at %s (%s)", svc.Name, mount.Target, access)
	if info, ok := bindSource(in, mount.Source); ok {
		switch {
		case info.State == "missing" && (mount.CreateHostPath == nil || *mount.CreateHostPath):
			detail += "; it does not exist, so the engine creates it as an empty directory owned by root"
		case info.State == "missing":
			detail += "; it does not exist and create_host_path is false, so the container is not created"
		default:
			detail += "; " + describePath(info)
		}
	}
	user, _ := containerUser(in, svc)
	if user == "" {
		user = "unknown"
	}
	detail += "; access for the container user (" + user + ") not verified — ACLs, user namespaces and SELinux are not read"
	if len(mount.Options) > 0 {
		detail += "; options not evaluated: " + strings.Join(mount.Options, ", ")
	}
	return detail
}
