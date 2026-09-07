// Package docker observes the host's container runtime: which engine is
// installed, which compose implementation it has, and the containers, networks,
// volumes and images that already exist on the machine.
//
// It only ever asks the runtime questions — every command it runs is on the
// published allowlist, and none of them starts, stops or removes anything.
//
// Two things this collector is deliberately careful about:
//
//   - "no runtime" and "a runtime that would not answer" are different answers.
//     The first leaves Capabilities.Runtime nil, which is what the rules act on.
//     The second sets Runtime.Reachable=false with a note and degrades the
//     section, because an empty container list on an unreachable daemon reads as
//     "this host runs nothing" — the single worst lie this package could tell.
//   - Nothing here reads a container's environment. `docker inspect` of a
//     container is not on the allowlist for exactly that reason, and neither the
//     names nor the values of a running container's variables are collected.
package docker

import (
	"fmt"
	"sort"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
)

// Runtime kinds, as model.ContainerRuntime.Kind spells them.
const (
	kindDocker = "docker"
	kindPodman = "podman"
)

// Compose implementation kinds, as model.ContainerRuntime.ComposeKind spells them.
const (
	composePlugin     = "plugin"
	composeStandalone = "standalone"
	composePodman     = "podman-compose"
)

// maxImageInspect bounds the number of `image inspect` calls.
//
// Architecture, OS and the true byte size are only available per image, one
// subprocess each, and a build host that has never been pruned carries hundreds
// of tags. 200 covers every image on any host a deployment is about to land on
// while keeping the worst case at a few seconds; images that share an id are
// inspected once, so a repository with five tags costs one call, not five. When
// the cap actually bites it is reported — a silently truncated result is the one
// thing this tool must never produce.
const maxImageInspect = 200

// maxNetworkInspect bounds the per-network subnet lookups, for the same reason:
// each network costs one subprocess, and a host running many compose projects has
// one network per project.
const maxNetworkInspect = 100

// Collect observes the container runtime and fills the runtime-related fields of
// caps.
func Collect(runner *run.Runner, caps *model.Capabilities, result *model.SectionResult) {
	kind := detect()
	if kind == "" {
		// Runtime stays nil, and that is an answer rather than a gap: a host with
		// no container engine is a finding in its own right, and it must not reach
		// the rules as an empty container list.
		result.Note("no container runtime found on PATH (docker, podman); the container checks did not run")
		return
	}

	runtime := &model.ContainerRuntime{Kind: kind}
	caps.Runtime = runtime

	runtime.Version = engineVersion(runner, kind)
	runtime.ComposeKind, runtime.ComposeVersion = composeImplementation(runner, kind)

	// `info` is asked first because it is the cheapest source of the storage
	// driver, but reachability is not decided from it: some docker versions print
	// the client half of `info` and exit 0 even when the daemon is unreachable.
	info, infoErr := runner.Output(kind, "info", "--format", "{{json .}}")
	if infoErr == nil {
		runtime.StorageDriver = parseStorageDriver(info)
	}

	// `ps` is the reachability probe: it cannot be answered without the daemon,
	// and it is the list whose emptiness would be misread.
	psOut, psErr := runner.Output(kind, "ps", "-a", "--format", "{{json .}}")
	if psErr != nil {
		runtime.Reachable = false
		runtime.Note = unreachableNote(kind, psErr)
		result.Degrade(runtime.Note)
		return
	}
	runtime.Reachable = true

	if infoErr != nil {
		note := fmt.Sprintf("%s info could not be read (%s); the storage driver is unknown",
			kind, shorten(infoErr.Error()))
		runtime.Note = note
		result.Degrade(note)
	}

	containers, warnings := parseContainers(psOut)
	noteWarnings(result, kind+" ps", warnings)
	sort.SliceStable(containers, func(i, j int) bool { return containers[i].Name < containers[j].Name })
	caps.Containers = containers

	caps.ContainerNetworks = listNetworks(runner, kind, result)
	caps.ContainerVolumes = listVolumes(runner, kind, result)
	caps.Images = listImages(runner, kind, result)
}

// detect picks the engine to interrogate: docker first, podman second.
//
// A host with both is asked about docker only. Interrogating both would double
// every list and leave no honest way to fill a single Runtime, and a machine that
// has docker installed is a machine whose deployments use it.
func detect() string {
	switch {
	case run.Available(kindDocker):
		return kindDocker
	case run.Available(kindPodman):
		return kindPodman
	default:
		return ""
	}
}

// engineVersion reads the engine version. Exit 1 is allowed on purpose: with the
// daemon down, the CLI still prints its own half of the version report and then
// fails, and the client version is worth keeping.
func engineVersion(runner *run.Runner, kind string) string {
	out, _, err := runner.OutputAllowExit([]int{1}, kind, "version", "--format", "{{json .}}")
	if strings.TrimSpace(out) == "" && err != nil {
		return ""
	}
	return parseEngineVersion(out)
}

// composeImplementation finds the compose implementation, if the host has one.
//
// Order matters: the V2 plugin is what a current host uses, and a machine that
// carries both answers for the plugin. A Podman host is asked about
// podman-compose first and then about a standalone docker-compose, which is a
// real configuration — docker-compose pointed at the podman socket — and is
// reported as the standalone binary it actually is.
func composeImplementation(runner *run.Runner, kind string) (composeKind, version string) {
	if kind == kindDocker {
		if out, err := runner.Output(kindDocker, "compose", "version", "--short"); err == nil {
			return composePlugin, parseVersionShort(out)
		}
	} else if run.Available("podman-compose") {
		if out, err := runner.Output("podman-compose", "version", "--short"); err == nil {
			return composePodman, parseVersionShort(out)
		}
	}
	if run.Available("docker-compose") {
		if out, err := runner.Output("docker-compose", "version", "--short"); err == nil {
			return composeStandalone, parseVersionShort(out)
		}
	}
	return "", ""
}

// listNetworks enumerates the runtime networks and looks up each one's subnets.
func listNetworks(runner *run.Runner, kind string, result *model.SectionResult) []model.ContainerNetwork {
	out, err := runner.Output(kind, "network", "ls", "--format", "{{json .}}")
	if err != nil {
		result.Degrade(fmt.Sprintf(
			"%s network ls failed (%s); the runtime network list is unknown, not empty",
			kind, shorten(err.Error())))
		return nil
	}

	networks, warnings := parseNetworkList(out)
	noteWarnings(result, kind+" network ls", warnings)

	inspected, skipped, failed, refused := 0, 0, 0, 0
	for i := range networks {
		if inspected >= maxNetworkInspect {
			skipped++
			continue
		}
		args := networkInspectArgs(kind, networks[i].Name)
		// Checked against the same allowlist the Runner enforces, so an unusual
		// name is counted here instead of being recorded as a refused command.
		if _, ok := run.Allowed(kind, args); !ok {
			refused++
			continue
		}
		inspected++
		detail, err := runner.Output(kind, args...)
		if err != nil {
			failed++
			continue
		}
		networks[i].Subnets = parseSubnets(detail)
	}

	if skipped > 0 {
		result.Note(fmt.Sprintf(
			"only the first %d runtime networks were inspected for subnets (cap %d); the address range of %d more is unknown",
			maxNetworkInspect, maxNetworkInspect, skipped))
	}
	if failed > 0 {
		result.Degrade(fmt.Sprintf(
			"%d of %d runtime networks could not be inspected; their subnets are unknown, not absent",
			failed, len(networks)))
	}
	if refused > 0 {
		result.Note(fmt.Sprintf(
			"%d runtime networks have a name this tool will not pass to a command, so their subnets were not read",
			refused))
	}

	sort.SliceStable(networks, func(i, j int) bool { return networks[i].Name < networks[j].Name })
	return networks
}

// networkInspectArgs is the allowlisted inspect form for each engine. Docker is
// asked for the IPAM block alone; podman keeps its subnets on the network object
// itself, so it is asked for the whole thing.
func networkInspectArgs(kind, name string) []string {
	if kind == kindDocker {
		return []string{"network", "inspect", name, "--format", "{{json .IPAM}}"}
	}
	return []string{"network", "inspect", name, "--format", "{{json .}}"}
}

// listVolumes enumerates the runtime volumes. `volume ls` already carries the
// mountpoint and the labels, so no per-volume inspect is needed.
func listVolumes(runner *run.Runner, kind string, result *model.SectionResult) []model.ContainerVolume {
	out, err := runner.Output(kind, "volume", "ls", "--format", "{{json .}}")
	if err != nil {
		result.Degrade(fmt.Sprintf(
			"%s volume ls failed (%s); the runtime volume list is unknown, not empty",
			kind, shorten(err.Error())))
		return nil
	}

	volumes, warnings := parseVolumeList(out)
	noteWarnings(result, kind+" volume ls", warnings)
	sort.SliceStable(volumes, func(i, j int) bool { return volumes[i].Name < volumes[j].Name })
	return volumes
}

// listImages enumerates the images on the host and fills each one's architecture,
// OS and size from a bounded number of `image inspect` calls.
func listImages(runner *run.Runner, kind string, result *model.SectionResult) []model.ContainerImage {
	out, err := runner.Output(kind, "image", "ls", "--all", "--digests", "--format", "{{json .}}")
	if err != nil {
		result.Degrade(fmt.Sprintf(
			"%s image ls failed (%s); the image list is unknown, not empty",
			kind, shorten(err.Error())))
		return nil
	}

	entries, warnings := parseImageList(out)
	noteWarnings(result, kind+" image ls", warnings)

	// Keyed by image id: the same image under five tags is five rows of
	// `image ls` and one call to `image inspect`.
	details := make(map[string]imageDetail, len(entries))
	images := make([]model.ContainerImage, 0, len(entries))
	inspected, skipped, failed := 0, 0, 0

	for _, entry := range entries {
		image := entry.Image

		detail, known := details[entry.ID]
		switch {
		case known:
		case inspected >= maxImageInspect:
			skipped++
		default:
			args := []string{"image", "inspect", entry.Ref, "--format", "{{json .}}"}
			if entry.Ref == "" {
				break
			}
			if _, ok := run.Allowed(kind, args); !ok {
				failed++
				break
			}
			// The attempt is what costs a subprocess, so it counts towards the cap
			// whether or not it answered.
			inspected++
			raw, inspectErr := runner.Output(kind, args...)
			if inspectErr != nil {
				failed++
				break
			}
			parsed, ok := parseImageInspect(raw)
			if !ok {
				failed++
				break
			}
			detail, known = parsed, true
			if entry.ID != "" {
				details[entry.ID] = parsed
			}
		}

		if known {
			image.Architecture = detail.Architecture
			image.OS = detail.OS
			if detail.SizeBytes > 0 {
				image.SizeBytes = detail.SizeBytes
			}
			if image.Digest == "" {
				image.Digest = detail.Digest
			}
		}
		images = append(images, image)
	}

	if skipped > 0 {
		result.Note(fmt.Sprintf(
			"the host carries more images than this audit inspects: %d of %d were left uninspected (cap %d), so their architecture, OS and size are unknown rather than absent",
			skipped, len(entries), maxImageInspect))
	}
	if failed > 0 {
		result.Degrade(fmt.Sprintf(
			"%d of %d images could not be inspected; their architecture, OS and size are unknown",
			failed, len(entries)))
	}

	sort.SliceStable(images, func(i, j int) bool { return images[i].Reference < images[j].Reference })
	return images
}

// unreachableNote explains an engine that is installed but would not answer. The
// wording is the point: the reader has to be able to tell this apart from a host
// with no containers, and to know what to do about it.
func unreachableNote(kind string, err error) string {
	reason := shorten(err.Error())
	if kind == kindDocker {
		return "docker is installed but its daemon could not be queried (" + reason +
			"); the container, network, volume and image lists are unknown rather than empty. " +
			"The usual cause is an unprivileged audit: /var/run/docker.sock is readable by root " +
			"and the docker group only — re-run as root, or as a member of that group, for the container checks"
	}
	return "podman is installed but could not be queried (" + reason +
		"); the container, network, volume and image lists are unknown rather than empty. " +
		"Rootless podman keeps a separate set of containers per account, so an audit run as one " +
		"user never sees another user's containers — re-run as the account that owns the deployment"
}

// noteWarnings records the lines a parser could not make sense of. Output that
// was not understood is not output that was empty.
func noteWarnings(result *model.SectionResult, source string, warnings []string) {
	if len(warnings) == 0 {
		return
	}
	shown := warnings
	if len(shown) > 3 {
		shown = shown[:3]
	}
	note := fmt.Sprintf("%s: %d entries could not be parsed (%s)",
		source, len(warnings), strings.Join(shown, "; "))
	result.Degrade(note)
}

// shorten collapses an error message into something that fits on one line of a
// CSV cell without losing the part that identifies the cause.
func shorten(msg string) string {
	msg = strings.Join(strings.Fields(msg), " ")
	const limit = 200
	if len(msg) > limit {
		return msg[:limit] + "…"
	}
	return msg
}
