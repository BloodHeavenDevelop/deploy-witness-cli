package witness

import (
	"fmt"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/collect/host"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// The capacity rules. All four share a discipline: they state the assumption they
// computed under, in the finding itself. A capacity claim without its assumption is
// unfalsifiable, and the reader has no way to tell a real shortfall from a manifest
// that simply declares generous reservations.

// diskPressureWarn and diskPressureBlock are the thresholds at which a filesystem
// stops being somebody else's problem. 90% is where filesystem performance starts
// degrading on most layouts and where an unattended deployment has no headroom;
// 97% is where writes begin failing.
const (
	diskPressureWarn  = 90.0
	diskPressureBlock = 97.0
	// minimumHeadroom is the space a container deployment needs beyond the images
	// themselves: layer extraction, logs, and the engine's own metadata.
	minimumHeadroom = int64(2) << 30
)

// 7. witness.insufficient_memory
func memoryShortfall(in Input) []model.Finding {
	if in.Caps.MemTotalBytes == 0 {
		return []model.Finding{{
			Code:       "witness.insufficient_memory",
			Category:   model.CategoryResource,
			Severity:   model.FindingInfo,
			Confidence: model.ConfidenceHigh,
			Title:      "Memory could not be measured",
			Description: "The host's memory was not readable, so the manifest's memory reservations were not " +
				"compared against anything.",
			WhyItMatters: "This is a gap in the audit, not a finding about the host. A deployment that would run " +
				"out of memory would not be flagged here.",
			WhatToDo: "Re-run the audit on the host itself if this report is expected to cover memory.",
			Evidence: []model.Evidence{evidence(in, "/proc/meminfo", "MemTotal could not be read")},
		}}
	}

	var reserved, limited int64
	var reserving, unreserved []string
	for _, svc := range in.Manifest.Services {
		switch {
		case svc.MemReservationBytes > 0:
			reserved += svc.MemReservationBytes
			reserving = append(reserving, fmt.Sprintf("%s reserves %s", svc.Name, humanBytes(svc.MemReservationBytes)))
		case svc.MemLimitBytes > 0:
			// A limit is not a reservation, but a service with a limit and no
			// reservation is still asking for room up to that limit.
			limited += svc.MemLimitBytes
			reserving = append(reserving, fmt.Sprintf("%s is limited to %s (no reservation)",
				svc.Name, humanBytes(svc.MemLimitBytes)))
		default:
			unreserved = append(unreserved, svc.Name)
		}
	}

	if reserved == 0 && limited == 0 {
		// Nothing to compare. Saying so is the honest answer: the manifest declares
		// no memory requirement at all, so "there is enough memory" would be a claim
		// about a number nobody supplied.
		return []model.Finding{{
			Code:       "witness.insufficient_memory",
			Category:   model.CategoryResource,
			Severity:   model.FindingInfo,
			Confidence: model.ConfidenceHigh,
			Title:      "The manifest declares no memory requirements",
			Description: fmt.Sprintf(
				"None of the %d service(s) sets deploy.resources.reservations.memory or a memory limit. "+
					"The host has %s total and %s available.",
				len(in.Manifest.Services), humanBytes(in.Caps.MemTotalBytes), humanBytes(in.Caps.MemAvailableBytes)),
			WhyItMatters: "Without a declared requirement there is nothing to check against, and a service that " +
				"grows until the kernel kills something is indistinguishable in advance from one that does not.",
			WhatToDo: "Declare reservations for the services whose appetite you know, so that this check can " +
				"do something useful on the next run.",
			Evidence: []model.Evidence{
				manifestEvidence(in, "", fmt.Sprintf("no deploy.resources.reservations.memory in any of: %s",
					strings.Join(serviceNames(in), ", "))),
				evidence(in, "/proc/meminfo", fmt.Sprintf("MemTotal %s, MemAvailable %s",
					humanBytes(in.Caps.MemTotalBytes), humanBytes(in.Caps.MemAvailableBytes))),
			},
		}}
	}

	need := reserved + limited
	if need <= in.Caps.MemAvailableBytes {
		return nil
	}

	severity := model.FindingWarning
	if need > in.Caps.MemTotalBytes {
		// More than the machine physically has. That is not a matter of what else
		// happens to be running.
		severity = model.FindingBlocker
	}

	assumption := fmt.Sprintf(
		"This is computed from what the manifest declares, not from measured usage: actual consumption under load "+
			"can be higher, and %d service(s) declare nothing at all (%s).",
		len(unreserved), strings.Join(unreserved, ", "))
	if len(unreserved) == 0 {
		assumption = "This is computed from what the manifest declares, not from measured usage: actual " +
			"consumption under load can be higher."
	}

	return []model.Finding{{
		Code:       "witness.insufficient_memory",
		Category:   model.CategoryResource,
		Severity:   severity,
		Confidence: model.ConfidenceMedium,
		Subject:    humanBytes(need),
		Title:      fmt.Sprintf("The deployment asks for %s of memory; %s is available", humanBytes(need), humanBytes(in.Caps.MemAvailableBytes)),
		Description: fmt.Sprintf("%s. The host has %s total, %s available and %s of swap. %s",
			strings.Join(reserving, "; "), humanBytes(in.Caps.MemTotalBytes),
			humanBytes(in.Caps.MemAvailableBytes), humanBytes(in.Caps.SwapTotalBytes), assumption),
		WhyItMatters: "When memory runs out the kernel picks a process to kill, and its choice is not the one you " +
			"would make. On a host with no swap the first symptom is usually an unrelated service disappearing.",
		WhatToDo: "Lower the reservations, deploy fewer services on this host, or add memory. If the reservations " +
			"are deliberately generous, this finding is the one to dismiss — after checking that they are.",
		Evidence: []model.Evidence{
			manifestEvidence(in, "", strings.Join(reserving, "\n")),
			evidence(in, "/proc/meminfo", fmt.Sprintf("MemTotal %s\nMemAvailable %s\nSwapTotal %s",
				humanBytes(in.Caps.MemTotalBytes), humanBytes(in.Caps.MemAvailableBytes),
				humanBytes(in.Caps.SwapTotalBytes))),
		},
	}}
}

func serviceNames(in Input) []string {
	out := make([]string, 0, len(in.Manifest.Services))
	for _, svc := range in.Manifest.Services {
		out = append(out, svc.Name)
	}
	return out
}

// 8. witness.insufficient_disk
func diskShortfall(in Input) []model.Finding {
	target, ok := deploymentFilesystem(in)
	if !ok {
		return []model.Finding{{
			Code:       "witness.insufficient_disk",
			Category:   model.CategoryResource,
			Severity:   model.FindingInfo,
			Confidence: model.ConfidenceHigh,
			Title:      "Free disk space could not be measured",
			Description: "No filesystem capacity was collected, so the space the deployment needs was not " +
				"compared against anything.",
			WhyItMatters: "This is a gap in the audit rather than a statement about the host.",
			WhatToDo:     "Re-run the audit on the host itself if this report is expected to cover disk space.",
			Evidence:     []model.Evidence{evidence(in, "/proc/mounts", "no filesystem could be measured")},
		}}
	}

	// What a deployment needs is the images it does not already have, and nobody can
	// know their size without contacting a registry. So the honest computation is:
	// the images already present cost nothing, the absent ones cost an unknown
	// amount, and the check is whether there is enough headroom for the unknown.
	present := map[string]bool{}
	for _, image := range in.Caps.Images {
		present[image.Reference] = true
	}

	var missing []string
	for _, svc := range in.Manifest.Services {
		if svc.Image.Raw == "" || svc.Build != "" {
			continue
		}
		if !present[svc.Image.Raw] {
			missing = append(missing, svc.Image.Raw)
		}
	}

	if len(missing) == 0 {
		return nil
	}
	if int64(target.AvailableBytes) >= minimumHeadroom {
		return nil
	}

	return []model.Finding{{
		Code:       "witness.insufficient_disk",
		Category:   model.CategoryResource,
		Severity:   model.FindingBlocker,
		Confidence: model.ConfidenceMedium,
		Subject:    target.Mount,
		Title: fmt.Sprintf("%s has %s free, and %d image(s) still have to be pulled",
			target.Mount, humanBytes(int64(target.AvailableBytes)), len(missing)),
		Description: fmt.Sprintf(
			"The deployment needs these images, none of which are on this host: %s. The filesystem holding the "+
				"container store (%s, %s) has %s available. How much the images need cannot be known without "+
				"contacting a registry, which this audit does not do — so this finding is about the headroom, not "+
				"about a measured requirement.",
			strings.Join(missing, ", "), target.Mount, target.FSType, humanBytes(int64(target.AvailableBytes))),
		WhyItMatters: "A pull that runs out of space fails partway through and leaves the engine holding partial " +
			"layers, which then have to be cleaned up before anything can be retried.",
		WhatToDo: fmt.Sprintf("Free space on %s before deploying — %s is not enough headroom for an image pull "+
			"plus layer extraction.", target.Mount, humanBytes(int64(target.AvailableBytes))),
		Evidence: []model.Evidence{
			manifestEvidence(in, "", "images not present on this host: "+strings.Join(missing, ", ")),
			evidence(in, "/proc/mounts + statfs("+target.Mount+")", fmt.Sprintf(
				"%s on %s (%s): %s of %s used, %s available",
				target.Mount, target.Device, target.FSType, humanBytes(int64(target.UsedBytes)),
				humanBytes(int64(target.TotalBytes)), humanBytes(int64(target.AvailableBytes)))),
		},
	}}
}

// deploymentFilesystem picks the filesystem the deployment will actually write to:
// the one holding the container store when it can be identified, and the root
// filesystem otherwise.
func deploymentFilesystem(in Input) (model.Filesystem, bool) {
	if len(in.Caps.Filesystems) == 0 {
		return model.Filesystem{}, false
	}
	root := "/var/lib/docker"
	if in.Caps.Runtime != nil && in.Caps.Runtime.Kind == "podman" {
		root = "/var/lib/containers"
	}
	if fs, ok := host.FilesystemFor(root, in.Caps.Filesystems); ok {
		return fs, true
	}
	return host.FilesystemFor("/", in.Caps.Filesystems)
}

// 9. witness.insufficient_inodes
func inodeShortfall(in Input) []model.Finding {
	target, ok := deploymentFilesystem(in)
	if !ok || target.InodesTotal == 0 {
		// Zero is not scarcity: btrfs and XFS with dynamic allocation report no
		// fixed inode count, and reading that as "none left" would produce a
		// confident finding about a limit that does not exist.
		return nil
	}

	usedPercent := float64(target.InodesTotal-target.InodesFree) / float64(target.InodesTotal) * 100
	if usedPercent < diskPressureWarn {
		return nil
	}

	severity := model.FindingWarning
	if usedPercent >= diskPressureBlock {
		severity = model.FindingBlocker
	}

	return []model.Finding{{
		Code:       "witness.insufficient_inodes",
		Category:   model.CategoryResource,
		Severity:   severity,
		Confidence: model.ConfidenceHigh,
		Subject:    target.Mount,
		Title:      fmt.Sprintf("%s has used %.1f%% of its inodes", target.Mount, usedPercent),
		Description: fmt.Sprintf(
			"%s (%s on %s) has %d of %d inodes in use and %d free, while %s of %s of its capacity is still unused.",
			target.Mount, target.FSType, target.Device, target.InodesTotal-target.InodesFree,
			target.InodesTotal, target.InodesFree,
			humanBytes(int64(target.AvailableBytes)), humanBytes(int64(target.TotalBytes))),
		WhyItMatters: "Running out of inodes fails writes with \"no space left on device\" while `df` still shows " +
			"free space, which is one of the more expensive hours an operator can spend. Container images are " +
			"thousands of small files, so a pull consumes inodes far faster than it consumes bytes.",
		WhatToDo: fmt.Sprintf("Remove unused files on %s — old images and layers first (`docker image prune` is "+
			"the usual answer, and it is yours to run, not this tool's).", target.Mount),
		Evidence: []model.Evidence{
			evidence(in, "/proc/mounts + statfs("+target.Mount+")", fmt.Sprintf(
				"%s inodes: %d total, %d free (%.1f%% used); bytes: %s of %s available",
				target.Mount, target.InodesTotal, target.InodesFree, usedPercent,
				humanBytes(int64(target.AvailableBytes)), humanBytes(int64(target.TotalBytes)))),
		},
	}}
}

// 24. witness.disk_at_limit
func diskPressure(in Input) []model.Finding {
	var out []model.Finding

	for _, fs := range in.Caps.Filesystems {
		if fs.TotalBytes == 0 || fs.ReadOnly {
			continue
		}
		usedPercent := float64(fs.UsedBytes) / float64(fs.TotalBytes) * 100
		if usedPercent < diskPressureWarn {
			continue
		}

		severity := model.FindingWarning
		if usedPercent >= diskPressureBlock {
			severity = model.FindingBlocker
		}

		out = append(out, model.Finding{
			Code:       "witness.disk_at_limit",
			Category:   model.CategoryResource,
			Severity:   severity,
			Confidence: model.ConfidenceHigh,
			Subject:    fs.Mount,
			Title:      fmt.Sprintf("%s is %.1f%% full", fs.Mount, usedPercent),
			Description: fmt.Sprintf("%s (%s on %s) holds %s of %s, leaving %s available.",
				fs.Mount, fs.FSType, fs.Device, humanBytes(int64(fs.UsedBytes)),
				humanBytes(int64(fs.TotalBytes)), humanBytes(int64(fs.AvailableBytes))),
			WhyItMatters: "A full filesystem takes down whatever writes to it, and a deployment writes to several " +
				"at once: images, volumes, logs. Databases in particular do not fail gracefully when they cannot write.",
			WhatToDo: fmt.Sprintf("Free space on %s before deploying.", fs.Mount),
			Evidence: []model.Evidence{
				evidence(in, "/proc/mounts + statfs("+fs.Mount+")", fmt.Sprintf(
					"%s on %s (%s): %s used of %s (%.1f%%), %s available",
					fs.Mount, fs.Device, fs.FSType, humanBytes(int64(fs.UsedBytes)),
					humanBytes(int64(fs.TotalBytes)), usedPercent, humanBytes(int64(fs.AvailableBytes)))),
			},
		})
	}
	return out
}
