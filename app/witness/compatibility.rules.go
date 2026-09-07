package witness

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// The compatibility rules: the deployment and the machine are each internally
// consistent, and wrong about each other.

// 10. witness.architecture_mismatch
func architectureMismatch(in Input) []model.Finding {
	hostArch := normaliseArch(in.Caps.Arch)
	if hostArch == "" {
		return nil
	}

	var out []model.Finding

	// The manifest's own `platform:` is the first place a mismatch shows, and it is
	// the one case that can be established without the image being present.
	for _, svc := range in.Manifest.Services {
		if svc.Platform == "" {
			continue
		}
		wanted := normaliseArch(platformArch(svc.Platform))
		if wanted == "" || wanted == hostArch {
			continue
		}
		out = append(out, model.Finding{
			Code:       "witness.architecture_mismatch",
			Category:   model.CategoryConflict,
			Severity:   model.FindingBlocker,
			Confidence: model.ConfidenceHigh,
			Subject:    svc.Name,
			Title:      fmt.Sprintf("Service %q asks for %s on a %s host", svc.Name, svc.Platform, in.Caps.Arch),
			Description: fmt.Sprintf(
				"The manifest pins service %q to platform %s. This host is %s.", svc.Name, svc.Platform, in.Caps.Arch),
			WhyItMatters: "Without an emulation layer installed the container will not start at all. With one, it " +
				"will start and run several times slower, which is harder to notice and worse to inherit.",
			WhatToDo: fmt.Sprintf("Remove the platform pin from %q, or build an image for %s.", svc.Name, hostArch),
			Evidence: []model.Evidence{
				manifestEvidence(in, svc.Name, "platform: "+svc.Platform),
				evidence(in, "uname -m", in.Caps.Arch),
			},
		})
	}

	// And for images already on the host, their own architecture is observable.
	byReference := map[string]model.ContainerImage{}
	for _, image := range in.Caps.Images {
		byReference[image.Reference] = image
	}
	for _, svc := range in.Manifest.Services {
		image, ok := byReference[svc.Image.Raw]
		if !ok || image.Architecture == "" {
			continue
		}
		if normaliseArch(image.Architecture) == hostArch {
			continue
		}
		out = append(out, model.Finding{
			Code:       "witness.architecture_mismatch",
			Category:   model.CategoryConflict,
			Severity:   model.FindingBlocker,
			Confidence: model.ConfidenceHigh,
			Subject:    svc.Image.Raw,
			SortOrder:  1,
			Title: fmt.Sprintf("Image %s is built for %s; this host is %s",
				svc.Image.Raw, image.Architecture, in.Caps.Arch),
			Description: fmt.Sprintf(
				"The image %s is already present on this host and reports architecture %s/%s. The host is %s.",
				svc.Image.Raw, image.OS, image.Architecture, in.Caps.Arch),
			WhyItMatters: "The container will fail with an exec format error, or run under emulation at a fraction " +
				"of the speed. Both are avoidable by pulling the right image.",
			WhatToDo: fmt.Sprintf("Pull %s for %s, or build it on this host.", svc.Image.Raw, hostArch),
			Evidence: []model.Evidence{
				manifestEvidence(in, svc.Name, "image: "+svc.Image.Raw),
				evidence(in, "docker image inspect "+svc.Image.Raw+" --format {{json .}}",
					fmt.Sprintf("architecture %s, os %s", image.Architecture, image.OS)),
				evidence(in, "uname -m", in.Caps.Arch),
			},
		})
	}
	return out
}

// platformArch takes the architecture out of an os/arch/variant string.
func platformArch(platform string) string {
	parts := strings.Split(platform, "/")
	if len(parts) < 2 {
		return platform
	}
	return parts[1]
}

// normaliseArch folds the several names each architecture answers to. uname says
// x86_64 where an image says amd64, and aarch64 where an image says arm64; comparing
// them literally reports a mismatch on every single arm host.
func normaliseArch(arch string) string {
	switch strings.ToLower(strings.TrimSpace(arch)) {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64", "arm64/v8", "armv8":
		return "arm64"
	case "armv7l", "armv7", "arm/v7":
		return "arm/v7"
	case "armv6l", "arm/v6":
		return "arm/v6"
	case "i386", "i686", "x86":
		return "386"
	case "riscv64":
		return "riscv64"
	case "ppc64le":
		return "ppc64le"
	case "s390x":
		return "s390x"
	case "":
		return ""
	default:
		return strings.ToLower(strings.TrimSpace(arch))
	}
}

// 11. witness.runtime_missing_or_old
func runtimeVersion(in Input) []model.Finding {
	if in.Caps.Runtime == nil {
		return []model.Finding{{
			Code:         "witness.runtime_missing_or_old",
			Category:     model.CategoryMissing,
			Severity:     model.FindingBlocker,
			Confidence:   model.ConfidenceHigh,
			Title:        "No container runtime is installed",
			Description:  "Neither docker nor podman was found on this host, and the manifest describes containers.",
			WhyItMatters: "There is nothing here that can run the deployment.",
			WhatToDo:     "Install a container engine and a Compose implementation before deploying.",
			Evidence: []model.Evidence{
				evidence(in, "PATH lookup of docker, podman", "neither binary is present"),
				manifestEvidence(in, "", fmt.Sprintf("%d service(s) declared", len(in.Manifest.Services))),
			},
		}}
	}

	var out []model.Finding
	runtime := in.Caps.Runtime

	if !runtime.Reachable {
		out = append(out, model.Finding{
			Code:       "witness.runtime_missing_or_old",
			Category:   model.CategoryMissing,
			Severity:   model.FindingWarning,
			Confidence: model.ConfidenceHigh,
			Subject:    runtime.Kind,
			Title:      fmt.Sprintf("%s is installed but did not answer", runtime.Kind),
			Description: fmt.Sprintf(
				"The %s binary is present, but querying the engine failed: %s. Every check that compares the "+
					"manifest against existing containers, networks, volumes and images was therefore skipped.",
				runtime.Kind, orUnknown(runtime.Note)),
			WhyItMatters: "This is the honesty case that matters most in this section: with the engine unreachable, " +
				"an empty conflict list means nothing was looked at, not that nothing is in the way.",
			WhatToDo: "Re-run the audit as a user who can reach the engine socket (root, or a member of the " +
				"docker group) to get the conflict checks.",
			Evidence: []model.Evidence{
				evidence(in, runtime.Kind+" info --format {{json .}}", orUnknown(runtime.Note)),
			},
		})
	}

	if runtime.ComposeKind == "" {
		out = append(out, model.Finding{
			Code:       "witness.runtime_missing_or_old",
			Category:   model.CategoryMissing,
			Severity:   model.FindingBlocker,
			Confidence: model.ConfidenceHigh,
			Subject:    "compose",
			SortOrder:  1,
			Title:      "No Compose implementation was found",
			Description: fmt.Sprintf(
				"%s %s is installed, but neither the `docker compose` plugin nor a standalone docker-compose "+
					"binary is available.", runtime.Kind, orUnknown(runtime.Version)),
			WhyItMatters: "The manifest is a Compose file. Without Compose, nothing reads it.",
			WhatToDo:     "Install the Compose plugin for the engine already on this host.",
			Evidence: []model.Evidence{
				evidence(in, "docker compose version --short / docker-compose version --short",
					"no compose implementation answered"),
			},
		})
	} else if runtime.ComposeKind == "standalone" {
		out = append(out, model.Finding{
			Code:       "witness.runtime_missing_or_old",
			Category:   model.CategoryMissing,
			Severity:   model.FindingWarning,
			Confidence: model.ConfidenceHigh,
			Subject:    "compose",
			SortOrder:  2,
			Title:      "Only the standalone Compose V1 is installed",
			Description: fmt.Sprintf(
				"This host has docker-compose %s (the Python V1 implementation) and not the V2 plugin.",
				orUnknown(runtime.ComposeVersion)),
			WhyItMatters: "Compose V1 reached end of life and does not understand several fields modern manifests " +
				"use — `deploy.resources` outside swarm mode, the long `depends_on` form with conditions, and " +
				"profiles among them. It ignores what it does not understand rather than refusing, so the " +
				"deployment comes up subtly different from what the file says.",
			WhatToDo: "Install the Compose V2 plugin and deploy with `docker compose` rather than `docker-compose`.",
			Evidence: []model.Evidence{
				evidence(in, "docker-compose version --short", orUnknown(runtime.ComposeVersion)),
			},
		})
	}

	return out
}

func orUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "no detail was reported"
	}
	return value
}

// 12. witness.registry_unreachable
func registryReachability(in Input) []model.Finding {
	registries := map[string][]string{}
	for _, svc := range in.Manifest.Services {
		if svc.Build != "" || svc.Image.Raw == "" {
			continue
		}
		registry := svc.Image.Registry
		if registry == "" {
			registry = "docker.io"
		}
		registries[registry] = append(registries[registry], svc.Name)
	}
	if len(registries) == 0 {
		return nil
	}

	if !in.EgressChecked {
		// The offline promise wins over the completeness of this check, and the
		// report says which. An audit that quietly omitted this would let a reader
		// conclude the registries are fine.
		var names []string
		for registry := range registries {
			names = append(names, registry)
		}
		return []model.Finding{{
			Code:       "witness.registry_unreachable",
			Category:   model.CategoryMissing,
			Severity:   model.FindingInfo,
			Confidence: model.ConfidenceHigh,
			Title:      "Registry reachability was not checked",
			Description: fmt.Sprintf(
				"The deployment pulls from %s. This audit does not open outbound connections unless asked, so "+
					"whether this host can reach them is unknown.", strings.Join(sortedKeys(registries), ", ")),
			WhyItMatters: "A host behind an egress firewall passes every other check in this report and then fails " +
				"at the pull. This line is here so that outcome is not a surprise.",
			WhatToDo: "Re-run with --egress to test reachability, or confirm outbound access to those registries " +
				"by other means.",
			Evidence: []model.Evidence{
				manifestEvidence(in, "", "registries referenced: "+strings.Join(names, ", ")),
			},
		}}
	}

	var out []model.Finding
	for _, registry := range sortedKeys(registries) {
		failure, checked := in.RegistryResults[registry]
		if !checked || failure == "" {
			continue
		}
		out = append(out, model.Finding{
			Code:       "witness.registry_unreachable",
			Category:   model.CategoryMissing,
			Severity:   model.FindingBlocker,
			Confidence: model.ConfidenceHigh,
			Subject:    registry,
			Title:      fmt.Sprintf("Registry %s is not reachable from this host", registry),
			Description: fmt.Sprintf("Reaching %s failed: %s. Service(s) %s pull from it.",
				registry, failure, strings.Join(registries[registry], ", ")),
			WhyItMatters: "The images cannot be pulled, so the deployment cannot start.",
			WhatToDo: fmt.Sprintf("Open outbound access to %s, or mirror the images into a registry this host "+
				"can reach.", registry),
			Evidence: []model.Evidence{
				manifestEvidence(in, "", "images from "+registry+": "+strings.Join(registries[registry], ", ")),
				evidence(in, "TCP connect to "+registry+":443 (--egress)", failure),
			},
		})
	}
	return out
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// 15. witness.database_version_mismatch
func databaseVersionMismatch(in Input) []model.Finding {
	var out []model.Finding

	for _, svc := range in.Manifest.Services {
		kind := databaseKindOfImage(svc.Image)
		if kind == "" {
			continue
		}
		wanted := majorVersion(svc.Image.Tag)
		if wanted == "" {
			continue
		}

		// The mismatch only bites when the service is pointed at data that already
		// exists — a bind mount of the host's data directory, or a named volume that
		// is already there. A fresh volume gets initialised by the new version and
		// there is nothing to be incompatible with.
		for _, db := range in.Caps.Databases {
			if db.Kind != kind || db.Version == "" {
				continue
			}
			have := majorVersion(db.Version)
			if have == "" || have == wanted {
				continue
			}
			mounted := mountsPath(svc, db.DataDir)
			severity := model.FindingWarning
			if mounted {
				severity = model.FindingBlocker
			}

			out = append(out, model.Finding{
				Code:       "witness.database_version_mismatch",
				Category:   model.CategoryConflict,
				Severity:   severity,
				Confidence: model.ConfidenceMedium,
				Subject:    svc.Name,
				Title: fmt.Sprintf("Service %q runs %s %s against %s %s data",
					svc.Name, kind, wanted, kind, have),
				Description: fmt.Sprintf(
					"The manifest asks for image %s (major version %s). This host already runs %s %s with its data "+
						"directory at %s%s.",
					svc.Image.Raw, wanted, kind, db.Version, orUnknown(db.DataDir),
					mountedSuffix(mounted, db.DataDir)),
				WhyItMatters: "A major-version mismatch is not a warning the engine gives you: PostgreSQL refuses " +
					"to start on a data directory from another major version, and MySQL will start and then need " +
					"an upgrade pass that is not reversible. Neither is something to discover during a deployment.",
				WhatToDo: fmt.Sprintf(
					"Match the image to the data (%s %s), or migrate the data deliberately with a dump and restore "+
						"before deploying. Take a backup first either way.", kind, have),
				Evidence: []model.Evidence{
					manifestEvidence(in, svc.Name, "image: "+svc.Image.Raw),
					evidence(in, db.DataDir+"/PG_VERSION or equivalent", fmt.Sprintf(
						"%s %s, data directory %s, %s", db.Kind, db.Version, db.DataDir, humanBytes(db.SizeBytes))),
				},
			})
		}
	}
	return out
}

func mountedSuffix(mounted bool, dataDir string) string {
	if mounted {
		return ", which this service bind-mounts (" + dataDir + ")"
	}
	return ""
}

// mountsPath reports whether a service bind-mounts a host path, or one containing it.
func mountsPath(svc model.ManifestService, path string) bool {
	if path == "" {
		return false
	}
	for _, mount := range svc.Volumes {
		if mount.Kind != model.MountBind {
			continue
		}
		if mount.Source == path || strings.HasPrefix(path, strings.TrimSuffix(mount.Source, "/")+"/") {
			return true
		}
	}
	return false
}

// databaseKindOfImage recognises the well-known database images by repository name.
func databaseKindOfImage(image model.ImageRef) string {
	repository := strings.ToLower(image.Repository)
	// The repository may be namespaced (library/postgres, bitnami/postgresql).
	if idx := strings.LastIndex(repository, "/"); idx >= 0 {
		repository = repository[idx+1:]
	}
	switch repository {
	case "postgres", "postgresql":
		return "postgres"
	case "mysql":
		return "mysql"
	case "mariadb":
		return "mariadb"
	case "mongo", "mongodb":
		return "mongodb"
	case "redis", "valkey":
		return "redis"
	}
	return ""
}

// majorVersion takes the leading numeric component of a version or tag. `latest`,
// `alpine` and anything else without one yield "" — which stops the rule rather than
// letting it compare nonsense.
func majorVersion(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	digits := ""
	for _, r := range value {
		if r < '0' || r > '9' {
			break
		}
		digits += string(r)
	}
	if digits == "" {
		return ""
	}
	if _, err := strconv.Atoi(digits); err != nil {
		return ""
	}
	return digits
}
