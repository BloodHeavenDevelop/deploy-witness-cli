package witness

import (
	"fmt"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// The remaining rules. None of them is about a collision; each is about something
// the deployment is missing, and they are the ones most often argued with — so each
// says plainly what it is claiming and, where the answer is a judgement, says that
// too.

// 16. witness.env_file_missing
func missingEnvFiles(in Input) []model.Finding {
	var out []model.Finding
	for _, svc := range in.Manifest.Services {
		for _, ref := range svc.EnvFiles {
			if ref.Exists {
				continue
			}
			out = append(out, model.Finding{
				Code:       "witness.env_file_missing",
				Category:   model.CategoryMissing,
				Severity:   model.FindingBlocker,
				Confidence: model.ConfidenceHigh,
				Subject:    ref.Path,
				Title:      fmt.Sprintf("env_file %s does not exist", ref.Path),
				Description: fmt.Sprintf(
					"Service %q reads its environment from %s, and that file is not present next to the manifest.",
					svc.Name, ref.Path),
				WhyItMatters: "Compose refuses to start a service whose env_file is missing. When it is present but " +
					"empty the failure is worse — the service starts with none of its configuration and fails later, " +
					"somewhere less obvious.",
				WhatToDo: fmt.Sprintf("Create %s before deploying, or remove the env_file entry from %q.",
					ref.Path, svc.Name),
				Evidence: []model.Evidence{
					manifestEvidence(in, svc.Name, "env_file: "+ref.Path),
					// The file's absence is the observation; its contents are never
					// read, here or anywhere else in this tool.
					evidence(in, "stat "+ref.Path, "no such file (the file's contents are never read by this audit)"),
				},
			})
		}
	}
	return out
}

// 17. witness.no_healthcheck
func missingHealthchecks(in Input) []model.Finding {
	var without []string
	for _, svc := range in.Manifest.Services {
		if !svc.HasHealthcheck {
			without = append(without, svc.Name)
		}
	}
	if len(without) == 0 {
		return nil
	}

	// One finding for the manifest rather than one per service: a stack with no
	// healthchecks at all is a single decision, and twelve identical findings would
	// bury the ones that are specific.
	return []model.Finding{{
		Code:        "witness.no_healthcheck",
		Category:    model.CategoryMissing,
		Severity:    model.FindingWarning,
		Confidence:  model.ConfidenceHigh,
		Subject:     strings.Join(without, ", "),
		Title:       fmt.Sprintf("%d of %d services define no healthcheck", len(without), len(in.Manifest.Services)),
		Description: fmt.Sprintf("These services have no healthcheck: %s.", strings.Join(without, ", ")),
		WhyItMatters: "Without one, the engine reports a container as running the moment its process starts, " +
			"which is not the same as the service being able to answer. A dependent service then starts against " +
			"something that is not ready yet, and `depends_on` cannot help — it waits for \"started\", not for " +
			"\"working\". A restart policy has the same blind spot: a process that is alive and wedged is never restarted.",
		WhatToDo: "Add a healthcheck to the services other things depend on, at minimum.",
		Evidence: []model.Evidence{
			manifestEvidence(in, "", "no healthcheck in: "+strings.Join(without, ", ")),
		},
	}}
}

// 18. witness.floating_image_tag
func floatingTags(in Input) []model.Finding {
	var out []model.Finding
	for _, svc := range in.Manifest.Services {
		if svc.Build != "" || svc.Image.Raw == "" || svc.Image.Pinned() {
			continue
		}
		tag := svc.Image.Tag
		if tag == "" {
			tag = "latest"
		}

		severity := model.FindingWarning
		title := fmt.Sprintf("Image %s is not pinned", svc.Image.Raw)
		description := fmt.Sprintf(
			"Service %q uses tag %q, which names a moving target rather than one image.", svc.Name, tag)
		if tag == "latest" {
			description = fmt.Sprintf(
				"Service %q uses the `latest` tag, which is whatever the registry pushed most recently.", svc.Name)
		}
		if majorVersion(tag) != "" && tag != "latest" {
			// A version-looking tag is a weaker case: it is still mutable, but the
			// blast radius of a moved `16.2` is smaller than that of `latest`.
			severity = model.FindingInfo
			title = fmt.Sprintf("Image %s is pinned by tag, not by digest", svc.Image.Raw)
		}

		out = append(out, model.Finding{
			Code:        "witness.floating_image_tag",
			Category:    model.CategoryMissing,
			Severity:    severity,
			Confidence:  model.ConfidenceHigh,
			Subject:     svc.Image.Raw,
			Title:       title,
			Description: description,
			WhyItMatters: "A tag can be moved. That makes the deployment unreproducible in the direction that " +
				"matters: rolling back to \"the version that worked\" pulls whatever the tag points at today, and " +
				"two hosts deployed a week apart from the same file are not running the same software.",
			WhatToDo: fmt.Sprintf("Pin %s by digest (image@sha256:…) once you have the version you want.",
				svc.Image.Repository),
			Evidence: []model.Evidence{
				manifestEvidence(in, svc.Name, "image: "+svc.Image.Raw),
			},
		})
	}
	return out
}

// 19. witness.privileged_container
func securityFlags(in Input) []model.Finding {
	var out []model.Finding

	for _, svc := range in.Manifest.Services {
		var reasons []string
		severity := model.FindingWarning

		if svc.Privileged {
			reasons = append(reasons, "privileged: true, which disables essentially every container boundary")
			severity = model.FindingBlocker
		}
		if svc.MountsContainerSocket {
			reasons = append(reasons,
				"it bind-mounts the container runtime socket, which is equivalent to root on the host")
			severity = model.FindingBlocker
		}
		if len(svc.CapAdd) > 0 {
			reasons = append(reasons, "cap_add: "+strings.Join(svc.CapAdd, ", "))
		}
		if len(svc.Devices) > 0 {
			reasons = append(reasons, "devices: "+strings.Join(svc.Devices, ", "))
		}
		if svc.NetworkMode == "host" {
			reasons = append(reasons,
				"network_mode: host, which puts the container directly on the host's network stack")
		}
		if len(reasons) == 0 {
			continue
		}

		out = append(out, model.Finding{
			Code:        "witness.privileged_container",
			Category:    model.CategorySecurity,
			Severity:    severity,
			Confidence:  model.ConfidenceHigh,
			Subject:     svc.Name,
			Title:       fmt.Sprintf("Service %q is granted authority over the host", svc.Name),
			Description: fmt.Sprintf("Service %q declares: %s.", svc.Name, strings.Join(reasons, "; ")),
			WhyItMatters: "These flags are sometimes genuinely required — a monitoring agent, a backup tool, a " +
				"container that manages other containers. The finding is not that they are wrong; it is that anyone " +
				"who compromises this service has the host, and that has to be a decision somebody made on purpose " +
				"rather than a line copied from an example.",
			WhatToDo: fmt.Sprintf("Confirm %q needs this. If it does, record why; if it does not, drop the flag — "+
				"a specific cap_add is almost always enough where privileged was used.", svc.Name),
			Evidence: []model.Evidence{
				manifestEvidence(in, svc.Name, strings.Join(reasons, "\n")),
			},
		})
	}
	return out
}

// backupStaleDays is when a backup stops counting as one. Long enough not to nag
// about a weekly schedule, short enough that a job which quietly stopped is caught.
const backupStaleDays = 30

// 20. witness.backup_gap
func backupGap(in Input) []model.Finding {
	backup := in.Caps.Backup

	// A deployment with no persistent data has nothing to lose, and telling its
	// owner to set up backups would be noise.
	if !hasPersistentData(in.Manifest) {
		return nil
	}

	switch {
	case len(backup.Tools) == 0 && len(backup.Locations) == 0:
		return []model.Finding{{
			Code:       "witness.backup_gap",
			Category:   model.CategoryMissing,
			Severity:   model.FindingWarning,
			Confidence: model.ConfidenceMedium,
			Title:      "No backup tooling or backup directory was found on this host",
			Description: fmt.Sprintf(
				"The deployment declares persistent data (%s), and nothing on this host looks like a backup: no "+
					"known backup tool is installed and none of the usual backup directories exist.%s",
				strings.Join(persistentData(in.Manifest), ", "), noteSuffix(backup.Note)),
			WhyItMatters: "The data this deployment creates would have to be recreated from nothing. That is a " +
				"decision worth making knowingly rather than discovering.",
			WhatToDo: "Set up a backup for the volumes and bind mounts this stack uses, before it starts holding " +
				"anything you would miss.",
			Evidence: []model.Evidence{
				manifestEvidence(in, "", "persistent data: "+strings.Join(persistentData(in.Manifest), ", ")),
				evidence(in, "PATH lookup of restic, borg, duplicity, rsnapshot; stat /backup /var/backups",
					"no backup tool and no backup directory found"+noteSuffix(backup.Note)),
			},
		}}

	case len(backup.Locations) > 0:
		var stale []string
		for _, location := range backup.Locations {
			if location.NewestFileAt == "" || location.AgeDays > backupStaleDays {
				stale = append(stale, fmt.Sprintf("%s (newest file %s)",
					location.Path, describeAge(location)))
			}
		}
		if len(stale) == 0 {
			return nil
		}
		return []model.Finding{{
			Code:       "witness.backup_gap",
			Category:   model.CategoryMissing,
			Severity:   model.FindingWarning,
			Confidence: model.ConfidenceMedium,
			Subject:    strings.Join(stale, ", "),
			Title:      "The backup directories on this host are stale",
			Description: fmt.Sprintf(
				"These backup locations exist but have not been written to recently: %s. Tools installed: %s.",
				strings.Join(stale, "; "), toolsOrNone(backup.Tools)),
			WhyItMatters: "An existing /backup directory reads as reassurance, and a stale one is worse than an " +
				"absent one for exactly that reason: the reassurance is false. Nothing here reads the contents of " +
				"a backup — the date is what tells a live backup from an abandoned one.",
			WhatToDo: "Check whether the backup job is still running, and whether it is still writing where you " +
				"think it is.",
			Evidence: []model.Evidence{
				evidence(in, "stat of the newest file under each backup directory",
					strings.Join(stale, "\n")),
			},
		}}
	}
	return nil
}

func toolsOrNone(tools []string) string {
	if len(tools) == 0 {
		return "none"
	}
	return strings.Join(tools, ", ")
}

func describeAge(location model.BackupLocation) string {
	if location.NewestFileAt == "" {
		return "none — the directory is empty or unreadable"
	}
	return fmt.Sprintf("%s, %d day(s) old", location.NewestFileAt, location.AgeDays)
}

func noteSuffix(note string) string {
	if strings.TrimSpace(note) == "" {
		return ""
	}
	return " " + note
}

// hasPersistentData reports whether the manifest declares anything worth backing up.
func hasPersistentData(manifest *model.Manifest) bool {
	return len(persistentData(manifest)) > 0
}

func persistentData(manifest *model.Manifest) []string {
	var out []string
	for _, svc := range manifest.Services {
		for _, mount := range svc.Volumes {
			switch mount.Kind {
			case model.MountVolume:
				out = append(out, fmt.Sprintf("volume %s (%s)", mount.Source, svc.Name))
			case model.MountBind:
				if !mount.ReadOnly {
					out = append(out, fmt.Sprintf("bind %s (%s)", mount.Source, svc.Name))
				}
			}
		}
	}
	return out
}

// 21. witness.no_rollback_plan
func rollbackGap(in Input) []model.Finding {
	plan := Rollback(in)

	var missing []string
	for _, item := range plan {
		if !item.Available {
			missing = append(missing, item.Kind+": "+item.Detail)
		}
	}
	if len(missing) == 0 {
		return nil
	}

	return []model.Finding{{
		Code:       "witness.no_rollback_plan",
		Category:   model.CategoryMissing,
		Severity:   model.FindingWarning,
		Confidence: model.ConfidenceHigh,
		Subject:    fmt.Sprintf("%d of %d", len(missing), len(plan)),
		Title:      "There is no way back from this deployment",
		Description: fmt.Sprintf(
			"The rollback plan for this host is incomplete. Missing: %s.", strings.Join(missing, "; ")),
		WhyItMatters: "Every other finding in this report is about whether the deployment will work. This one is " +
			"about what happens when it does not, and it is the only one that cannot be fixed after the fact.",
		WhatToDo: "Before deploying: note the image digests currently running, copy the web server configuration " +
			"somewhere outside this host, and take a snapshot or a volume backup.",
		Evidence: []model.Evidence{
			evidence(in, "the rollback section of this report", strings.Join(missing, "\n")),
		},
	}}
}

// certificateExpiryWarnDays and certificateExpiryBlockDays: 30 days is when a
// renewal that has silently stopped can still be fixed calmly; 7 is when it cannot.
const (
	certificateExpiryWarnDays  = 30
	certificateExpiryBlockDays = 7
)

// 22. witness.certificate_expiring
func certificateExpiry(in Input) []model.Finding {
	var out []model.Finding

	for _, cert := range in.Caps.Certificates {
		if cert.NotAfter == "" {
			continue
		}
		if cert.DaysLeft > certificateExpiryWarnDays {
			continue
		}

		severity := model.FindingWarning
		if cert.DaysLeft <= certificateExpiryBlockDays {
			severity = model.FindingBlocker
		}

		title := fmt.Sprintf("Certificate for %s expires in %d day(s)", certificateName(cert), cert.DaysLeft)
		if cert.DaysLeft < 0 {
			title = fmt.Sprintf("Certificate for %s expired %d day(s) ago", certificateName(cert), -cert.DaysLeft)
			severity = model.FindingBlocker
		}

		renewal := "Nothing on this host claims to renew it."
		if cert.Manager != "" && cert.AutoRenew {
			renewal = fmt.Sprintf("%s manages it and a renewal job was found.", cert.Manager)
		} else if cert.Manager != "" {
			renewal = fmt.Sprintf("%s issued it, but no renewal job for it was found — which is not the same as "+
				"%s being installed.", cert.Manager, cert.Manager)
		}

		out = append(out, model.Finding{
			Code:       "witness.certificate_expiring",
			Category:   model.CategoryExpiry,
			Severity:   severity,
			Confidence: model.ConfidenceHigh,
			Subject:    cert.Path,
			SortOrder:  cert.DaysLeft,
			Title:      title,
			Description: fmt.Sprintf("%s covers %s, issued by %s, valid until %s. %s",
				cert.Path, namesOrSubject(cert), orUnknown(cert.Issuer), cert.NotAfter, renewal),
			WhyItMatters: "An expired certificate takes the site down in every browser at once, and it does it " +
				"at a time nobody chose. A deployment is the moment this is cheap to fix.",
			WhatToDo: renewalAdvice(cert),
			Evidence: []model.Evidence{
				evidence(in, cert.Path, fmt.Sprintf("subject %s\nSANs %s\nissuer %s\nnotAfter %s\nself-signed %t",
					orUnknown(cert.Subject), strings.Join(cert.SANs, ", "), orUnknown(cert.Issuer),
					cert.NotAfter, cert.SelfSigned)),
			},
		})
	}
	return out
}

func certificateName(cert model.Certificate) string {
	if len(cert.SANs) > 0 {
		return cert.SANs[0]
	}
	if cert.Subject != "" {
		return cert.Subject
	}
	return cert.Path
}

func namesOrSubject(cert model.Certificate) string {
	if len(cert.SANs) > 0 {
		return strings.Join(cert.SANs, ", ")
	}
	return orUnknown(cert.Subject)
}

func renewalAdvice(cert model.Certificate) string {
	switch {
	case cert.Manager != "" && !cert.AutoRenew:
		return fmt.Sprintf("Find out why %s is not renewing it — the tool is present, so the schedule or the "+
			"renewal configuration is what is missing.", cert.Manager)
	case cert.Manager == "":
		return "Renew it, and put something in place that renews it next time."
	default:
		return "Confirm the renewal actually runs — the job exists, so check its last outcome."
	}
}

// 23. witness.reboot_required
func rebootPending(in Input) []model.Finding {
	if in.Caps.RebootRequired != "yes" {
		return nil
	}
	return []model.Finding{{
		Code:        "witness.reboot_required",
		Category:    model.CategoryMissing,
		Severity:    model.FindingWarning,
		Confidence:  model.ConfidenceHigh,
		Title:       "This host is waiting for a reboot",
		Description: "The running kernel or libraries are older than the ones installed, so a reboot is pending.",
		WhyItMatters: "Deploying now means the next reboot — whenever it happens, possibly not chosen by you — " +
			"restarts the host with both a new kernel and a new deployment at once. If something then fails, " +
			"there are two changes to untangle instead of one.",
		WhatToDo: "Reboot before deploying, or decide deliberately to carry the pending reboot forward.",
		Evidence: []model.Evidence{
			evidence(in, "needs-restarting -r / /var/run/reboot-required", "a reboot is required"),
		},
	}}
}
