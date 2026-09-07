package docker

// The parsers live apart from the collector on purpose: every one of them takes a
// string and returns model types, so the whole of this package's understanding of
// docker and podman output is testable against captured fixtures, with no daemon
// and no network anywhere near the test.
//
// Docker and podman answer the same questions in different shapes, and the
// differences are not cosmetic:
//
//	                docker `--format {{json .}}`        podman
//	  container names  "web"            (string)        ["web"]        (array)
//	  labels           "a=1,b=2"        (string)         {"a":"1"}     (object)
//	  ports            "0.0.0.0:8080->80/tcp" (string)   [{host_port…}] (array)
//	  networks         "bridge,web"     (string)        ["bridge"]     (array)
//	  image size       "191MB"          (string)         191000000     (number)
//	  network subnets  .IPAM.Config[].Subnet             subnets[].subnet
//
// A parser that assumes docker's shape reports a podman host as empty, which is
// why every one of these fields goes through a decoder that accepts both.

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// Compose labels.
//
// These two are load-bearing rather than decorative: they are how a later rule
// tells "port 8080 is held by an unrelated service" from "port 8080 is held by
// the previous version of this very deployment". Docker Compose and Podman's own
// compose provider both write the com.docker.compose.* pair; podman-compose has
// historically also written an io.podman.compose.* pair, so both prefixes are
// read and the docker one wins when a container carries both.
const (
	labelDockerProject = "com.docker.compose.project"
	labelDockerService = "com.docker.compose.service"
	labelPodmanProject = "io.podman.compose.project"
	labelPodmanService = "io.podman.compose.service"
)

// noneValue is what docker prints for an absent repository, tag or digest. It is
// a placeholder, not a value, and it never reaches the report.
const noneValue = "<none>"

// ───────────────────────────────────────────────── flexible field decoders

// flexStrings decodes a field docker renders as a comma-separated string and
// podman renders as a JSON array.
type flexStrings []string

func (f *flexStrings) UnmarshalJSON(raw []byte) error {
	text := strings.TrimSpace(string(raw))
	if text == "" || text == "null" {
		return nil
	}
	if strings.HasPrefix(text, "[") {
		var items []string
		if err := json.Unmarshal(raw, &items); err != nil {
			return err
		}
		out := make([]string, 0, len(items))
		for _, item := range items {
			if item = strings.TrimSpace(item); item != "" {
				out = append(out, item)
			}
		}
		*f = out
		return nil
	}
	var joined string
	if err := json.Unmarshal(raw, &joined); err != nil {
		return err
	}
	*f = splitList(joined)
	return nil
}

// flexLabels decodes labels from either shape.
//
// Docker's `ps --format {{json .}}` hands them over as one `k=v,k=v` string,
// which is ambiguous for a label whose value contains a comma — there is no
// escaping in that format, so a value like `a,b` is indistinguishable from two
// labels. The compose labels this collector needs never contain one, and the
// split is documented here rather than silently assumed.
type flexLabels map[string]string

func (l *flexLabels) UnmarshalJSON(raw []byte) error {
	text := strings.TrimSpace(string(raw))
	if text == "" || text == "null" {
		return nil
	}
	if strings.HasPrefix(text, "{") {
		var pairs map[string]string
		if err := json.Unmarshal(raw, &pairs); err != nil {
			return err
		}
		*l = pairs
		return nil
	}
	var packed string
	if err := json.Unmarshal(raw, &packed); err != nil {
		return err
	}
	pairs := make(map[string]string)
	for _, item := range splitList(packed) {
		key, value, found := strings.Cut(item, "=")
		if key = strings.TrimSpace(key); key == "" {
			continue
		}
		if !found {
			pairs[key] = ""
			continue
		}
		pairs[key] = strings.TrimSpace(value)
	}
	*l = pairs
	return nil
}

// flexPorts decodes a published-port list from either shape.
type flexPorts []model.PortMapping

func (p *flexPorts) UnmarshalJSON(raw []byte) error {
	text := strings.TrimSpace(string(raw))
	if text == "" || text == "null" {
		return nil
	}
	if strings.HasPrefix(text, "[") {
		var items []podmanPort
		if err := json.Unmarshal(raw, &items); err != nil {
			return err
		}
		var out []model.PortMapping
		for _, item := range items {
			out = append(out, item.mappings()...)
		}
		*p = out
		return nil
	}
	var packed string
	if err := json.Unmarshal(raw, &packed); err != nil {
		return err
	}
	*p = parsePortString(packed)
	return nil
}

// podmanPort is one entry of podman's structured port list.
type podmanPort struct {
	HostIP        string `json:"host_ip"`
	ContainerPort int    `json:"container_port"`
	HostPort      int    `json:"host_port"`
	// Range is a count, not an end port: 1 is a single port, 3 means this and the
	// two after it.
	Range int `json:"range"`
	// Protocol is usually "tcp", and is comma-separated when one mapping covers
	// several protocols.
	Protocol string `json:"protocol"`
}

func (p podmanPort) mappings() []model.PortMapping {
	end := 0
	if p.Range > 1 {
		end = p.HostPort + p.Range - 1
	}
	protocols := splitList(p.Protocol)
	if len(protocols) == 0 {
		// Podman omits the protocol for the default case.
		protocols = []string{"tcp"}
	}
	out := make([]model.PortMapping, 0, len(protocols))
	for _, protocol := range protocols {
		out = append(out, model.PortMapping{
			HostIP:        p.HostIP,
			HostPort:      p.HostPort,
			HostPortEnd:   end,
			ContainerPort: p.ContainerPort,
			Protocol:      strings.ToLower(protocol),
		})
	}
	return out
}

// flexBytes decodes a size that podman reports as a number of bytes and docker
// reports as a human string.
//
// The human form is deliberately not parsed: docker rounds it to three
// significant digits, so "191MB" would enter the report as a byte count that is
// wrong by megabytes. `image inspect` gives the exact number for every image
// inside the inspect cap, and beyond the cap the size stays zero and the cap is
// reported.
type flexBytes int64

func (v *flexBytes) UnmarshalJSON(raw []byte) error {
	text := strings.TrimSpace(string(raw))
	if text == "" || text == "null" {
		return nil
	}
	if strings.HasPrefix(text, `"`) {
		return nil
	}
	var size float64
	if err := json.Unmarshal(raw, &size); err != nil {
		return err
	}
	*v = flexBytes(size)
	return nil
}

// ───────────────────────────────────────────────────────────── containers

// psEntry is one row of `ps -a --format {{json .}}` in either dialect. Go's JSON
// decoder matches field names case-insensitively, which is what lets podman's
// lowercased keys land in the same struct.
type psEntry struct {
	ID       string      `json:"ID"`
	Names    flexStrings `json:"Names"`
	Image    string      `json:"Image"`
	State    string      `json:"State"`
	Status   string      `json:"Status"`
	Ports    flexPorts   `json:"Ports"`
	Networks flexStrings `json:"Networks"`
	Labels   flexLabels  `json:"Labels"`
}

// parseContainers reads the container list. The second return value is what could
// not be parsed, which the caller reports rather than discards.
func parseContainers(out string) ([]model.Container, []string) {
	var containers []model.Container
	warnings := decodeJSON(out, func(raw json.RawMessage) error {
		var entry psEntry
		if err := json.Unmarshal(raw, &entry); err != nil {
			return err
		}
		container := model.Container{
			Name:     containerName(entry),
			Image:    strings.TrimSpace(entry.Image),
			State:    normalizeState(entry.State, entry.Status),
			Status:   strings.TrimSpace(entry.Status),
			Ports:    entry.Ports,
			Networks: entry.Networks,
			Project:  labelValue(entry.Labels, labelDockerProject, labelPodmanProject),
			Service:  labelValue(entry.Labels, labelDockerService, labelPodmanService),
		}
		containers = append(containers, container)
		return nil
	})
	return containers, warnings
}

// containerName picks the name to report. A container can carry several; the
// first is the one every tool prints. A container with none is identified by its
// id, because a row with an empty name is unusable to the reader.
func containerName(entry psEntry) string {
	for _, name := range entry.Names {
		if name = strings.TrimPrefix(strings.TrimSpace(name), "/"); name != "" {
			return name
		}
	}
	return strings.TrimSpace(entry.ID)
}

// normalizeState reports the container state in the lower-case vocabulary both
// engines share (running, exited, created, paused…).
//
// Older podman leaves State empty and puts everything in Status, so the state is
// recovered from the status line rather than reported as unknown. When neither
// says anything the state stays empty — which is honest, and not the same as
// "exited".
func normalizeState(state, status string) string {
	if state = strings.ToLower(strings.TrimSpace(state)); state != "" {
		return state
	}
	status = strings.ToLower(strings.TrimSpace(status))
	switch {
	case strings.HasPrefix(status, "up"):
		return "running"
	case strings.HasPrefix(status, "exited"), strings.HasPrefix(status, "exit"):
		return "exited"
	case strings.HasPrefix(status, "created"):
		return "created"
	case strings.HasPrefix(status, "paused"):
		return "paused"
	case strings.HasPrefix(status, "restarting"):
		return "restarting"
	default:
		return ""
	}
}

// ───────────────────────────────────────────────────────────────── ports

// parsePortString parses docker's published-port string, e.g.
//
//	0.0.0.0:8080->80/tcp, [::]:8080->80/tcp, 127.0.0.1:5432->5432/tcp
//	0.0.0.0:8000-8010->8000-8010/tcp
//	80/tcp
//
// The IPv4 and IPv6 halves of one publication are kept as two mappings rather
// than merged: they differ in HostIP, which is exactly the field a rule about
// exposure reads.
//
// An entry with no `->` is a port the image exposes without publishing it. It is
// kept with HostPort zero, which model.PortMapping.HostPorts() already reads as
// "claims no host port".
func parsePortString(packed string) []model.PortMapping {
	var out []model.PortMapping
	for _, entry := range strings.Split(packed, ",") {
		if entry = strings.TrimSpace(entry); entry == "" {
			continue
		}
		if mapping, ok := parsePortEntry(entry); ok {
			out = append(out, mapping)
		}
	}
	return out
}

func parsePortEntry(entry string) (model.PortMapping, bool) {
	host, container, published := strings.Cut(entry, "->")
	if !published {
		container, host = entry, ""
	}

	container = strings.TrimSpace(container)
	protocol := ""
	if body, proto, found := cutLast(container, "/"); found {
		container, protocol = body, strings.ToLower(strings.TrimSpace(proto))
	}
	if protocol == "" {
		protocol = "tcp"
	}

	// A container-side range publishes one host port per container port; the model
	// carries the range on the host side, so the container side keeps its first
	// port.
	containerPort, _ := parsePortRange(container)
	mapping := model.PortMapping{ContainerPort: containerPort, Protocol: protocol}

	if host = strings.TrimSpace(host); host != "" {
		ip, portSpec := splitHostPort(host)
		mapping.HostIP = ip
		start, end := parsePortRange(portSpec)
		mapping.HostPort = start
		if end > start {
			mapping.HostPortEnd = end
		}
	}
	if mapping.HostPort == 0 && mapping.ContainerPort == 0 {
		return model.PortMapping{}, false
	}
	return mapping, true
}

// splitHostPort separates the address from the port specification, in every form
// docker prints one: 0.0.0.0:8080, [::]:8080, :::8080, or a bare 8080.
func splitHostPort(host string) (ip, portSpec string) {
	if strings.HasPrefix(host, "[") {
		if idx := strings.Index(host, "]"); idx > 0 {
			ip = host[1:idx]
			portSpec = strings.TrimPrefix(host[idx+1:], ":")
			return ip, portSpec
		}
	}
	idx := strings.LastIndex(host, ":")
	if idx < 0 {
		return "", host
	}
	return host[:idx], host[idx+1:]
}

// parsePortRange reads "8080" or "8000-8010".
func parsePortRange(spec string) (start, end int) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0, 0
	}
	first, second, found := strings.Cut(spec, "-")
	start = atoi(first)
	if found {
		end = atoi(second)
	}
	return start, end
}

// ────────────────────────────────────────────────────────────── networks

type networkEntry struct {
	Name   string     `json:"Name"`
	Driver string     `json:"Driver"`
	Labels flexLabels `json:"Labels"`
}

// parseNetworkList reads `network ls`. Subnets are not in that output for either
// engine; they come from the per-network inspect.
func parseNetworkList(out string) ([]model.ContainerNetwork, []string) {
	var networks []model.ContainerNetwork
	warnings := decodeJSON(out, func(raw json.RawMessage) error {
		var entry networkEntry
		if err := json.Unmarshal(raw, &entry); err != nil {
			return err
		}
		name := strings.TrimSpace(entry.Name)
		if name == "" {
			return nil
		}
		networks = append(networks, model.ContainerNetwork{
			Name:    name,
			Driver:  strings.TrimSpace(entry.Driver),
			Project: labelValue(entry.Labels, labelDockerProject, labelPodmanProject),
		})
		return nil
	})
	return networks, warnings
}

// subnetProbe accepts every shape a network's address range arrives in:
//
//   - docker `network inspect --format {{json .IPAM}}` — Config[].Subnet
//   - a whole docker network object — IPAM.Config[].Subnet
//   - podman with netavark — subnets[].subnet
//   - podman with CNI (pre-4.0) — plugins[].ipam.ranges[][].subnet
//
// Reading all four from one struct is what keeps the caller from having to know
// which engine version it is talking to.
type subnetProbe struct {
	Config  []subnetEntry `json:"Config"`
	IPAM    *subnetProbe  `json:"IPAM"`
	Subnets []subnetEntry `json:"subnets"`
	Plugins []struct {
		IPAM struct {
			Ranges [][]subnetEntry `json:"ranges"`
		} `json:"ipam"`
	} `json:"plugins"`
}

type subnetEntry struct {
	Subnet string `json:"subnet"`
}

// parseSubnets extracts the CIDR ranges from a network inspect. An empty result
// is a network with no IPAM configuration — a host network, or macvlan without an
// explicit range — and the caller separately reports an inspect that failed.
func parseSubnets(out string) []string {
	var subnets []string
	decodeJSON(out, func(raw json.RawMessage) error {
		var probe subnetProbe
		if err := json.Unmarshal(raw, &probe); err != nil {
			return err
		}
		subnets = append(subnets, probe.collect()...)
		return nil
	})
	if len(subnets) == 0 {
		return nil
	}
	return subnets
}

func (p subnetProbe) collect() []string {
	var out []string
	add := func(entries []subnetEntry) {
		for _, entry := range entries {
			if cidr := strings.TrimSpace(entry.Subnet); cidr != "" {
				out = append(out, cidr)
			}
		}
	}
	add(p.Config)
	add(p.Subnets)
	for _, plugin := range p.Plugins {
		for _, group := range plugin.IPAM.Ranges {
			add(group)
		}
	}
	if p.IPAM != nil {
		out = append(out, p.IPAM.collect()...)
	}
	return out
}

// ─────────────────────────────────────────────────────────────── volumes

type volumeEntry struct {
	Name       string     `json:"Name"`
	Driver     string     `json:"Driver"`
	Mountpoint string     `json:"Mountpoint"`
	Labels     flexLabels `json:"Labels"`
}

// parseVolumeList reads `volume ls`.
func parseVolumeList(out string) ([]model.ContainerVolume, []string) {
	var volumes []model.ContainerVolume
	warnings := decodeJSON(out, func(raw json.RawMessage) error {
		var entry volumeEntry
		if err := json.Unmarshal(raw, &entry); err != nil {
			return err
		}
		name := strings.TrimSpace(entry.Name)
		if name == "" {
			return nil
		}
		volumes = append(volumes, model.ContainerVolume{
			Name:       name,
			Driver:     strings.TrimSpace(entry.Driver),
			Mountpoint: strings.TrimSpace(entry.Mountpoint),
			Project:    labelValue(entry.Labels, labelDockerProject, labelPodmanProject),
		})
		return nil
	})
	return volumes, warnings
}

// ──────────────────────────────────────────────────────────────── images

// imageEntry is one row of `image ls`, plus the handle a follow-up inspect has to
// use. A dangling image has no name at all, so its id is the only thing that
// identifies it.
type imageEntry struct {
	Image model.ContainerImage
	// Ref is what to pass to `image inspect`: the reference when there is one,
	// the id otherwise.
	Ref string
	// ID groups the rows that are the same image under different tags, so it is
	// inspected once.
	ID string
}

type imageListEntry struct {
	ID         string      `json:"ID"`
	Repository string      `json:"Repository"`
	Tag        string      `json:"Tag"`
	Digest     string      `json:"Digest"`
	Names      flexStrings `json:"Names"`
	Size       flexBytes   `json:"Size"`
}

// parseImageList reads `image ls --all --digests`.
func parseImageList(out string) ([]imageEntry, []string) {
	var images []imageEntry
	warnings := decodeJSON(out, func(raw json.RawMessage) error {
		var entry imageListEntry
		if err := json.Unmarshal(raw, &entry); err != nil {
			return err
		}
		reference := entry.reference()
		id := strings.TrimSpace(entry.ID)
		if reference == "" && id == "" {
			return nil
		}
		ref := reference
		if ref == "" {
			// A dangling image has no name. Its id is what identifies it — to the
			// engine, to `image inspect` and to the reader of the report — so it
			// stands in as the reference rather than leaving a blank row.
			ref = id
			reference = id
		}
		images = append(images, imageEntry{
			Image: model.ContainerImage{
				Reference: reference,
				Digest:    cleanDigest(entry.Digest),
				SizeBytes: int64(entry.Size),
			},
			Ref: ref,
			ID:  id,
		})
		return nil
	})
	return images, warnings
}

// reference builds the image reference from whichever fields the engine filled.
// Docker splits it into Repository and Tag; podman hands over a Names array of
// fully qualified references.
func (e imageListEntry) reference() string {
	repository := clean(e.Repository)
	tag := clean(e.Tag)
	switch {
	case repository != "" && tag != "":
		return repository + ":" + tag
	case repository != "":
		return repository
	}
	for _, name := range e.Names {
		if name = clean(name); name != "" {
			return name
		}
	}
	return ""
}

// imageDetail is what `image inspect` adds to a listed image.
type imageDetail struct {
	Architecture string
	OS           string
	SizeBytes    int64
	Digest       string
}

type imageInspectEntry struct {
	Architecture string    `json:"Architecture"`
	OS           string    `json:"Os"`
	Size         flexBytes `json:"Size"`
	Digest       string    `json:"Digest"`
	RepoDigests  []string  `json:"RepoDigests"`
}

// parseImageInspect reads one `image inspect`. It reports false when the output
// held nothing usable, so the caller can count the failure instead of recording
// an image with a blank architecture as if the engine had said so.
func parseImageInspect(out string) (imageDetail, bool) {
	var detail imageDetail
	found := false
	decodeJSON(out, func(raw json.RawMessage) error {
		var entry imageInspectEntry
		if err := json.Unmarshal(raw, &entry); err != nil {
			return err
		}
		if found {
			return nil
		}
		detail = imageDetail{
			Architecture: strings.TrimSpace(entry.Architecture),
			OS:           strings.TrimSpace(entry.OS),
			SizeBytes:    int64(entry.Size),
			Digest:       cleanDigest(entry.Digest),
		}
		if detail.Digest == "" {
			for _, repoDigest := range entry.RepoDigests {
				if _, digest, ok := strings.Cut(repoDigest, "@"); ok {
					detail.Digest = cleanDigest(digest)
					break
				}
			}
		}
		found = detail != (imageDetail{})
		return nil
	})
	return detail, found
}

// ──────────────────────────────────────────────────────── info and version

// parseStorageDriver reads the storage driver from `info`. Docker keeps it at the
// top level as Driver; podman keeps it under store.graphDriverName.
func parseStorageDriver(out string) string {
	var info struct {
		Driver string `json:"Driver"`
		Store  struct {
			GraphDriverName string `json:"graphDriverName"`
		} `json:"store"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &info); err != nil {
		return ""
	}
	if driver := strings.TrimSpace(info.Driver); driver != "" {
		return driver
	}
	return strings.TrimSpace(info.Store.GraphDriverName)
}

// parseEngineVersion reads `version --format {{json .}}`. The server version is
// the engine's own and is preferred; the client version is the fallback, and it
// is all there is when the daemon did not answer.
func parseEngineVersion(out string) string {
	var version struct {
		Client struct {
			Version string `json:"Version"`
		} `json:"Client"`
		Server *struct {
			Version string `json:"Version"`
		} `json:"Server"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &version); err != nil {
		return ""
	}
	if version.Server != nil {
		if v := strings.TrimSpace(version.Server.Version); v != "" {
			return v
		}
	}
	return strings.TrimSpace(version.Client.Version)
}

// parseVersionShort reads a `version --short` line. `docker compose` prints
// "v2.24.5"; podman-compose has printed a whole sentence in some releases, so the
// first version-looking token wins and the leading v is dropped.
func parseVersionShort(out string) string {
	for _, line := range strings.Split(out, "\n") {
		for _, field := range strings.Fields(line) {
			candidate := strings.TrimPrefix(field, "v")
			if candidate == "" {
				continue
			}
			if candidate[0] >= '0' && candidate[0] <= '9' {
				return candidate
			}
		}
	}
	return ""
}

// ─────────────────────────────────────────────────────────────── helpers

// decodeJSON walks a runtime's JSON output in whichever of its two shapes it
// arrived: `--format {{json .}}` emits one object per line, while `--format json`
// — and podman for some subcommands even when asked for the template — emits a
// single array. Returned warnings are the entries that could not be read.
func decodeJSON(out string, visit func(json.RawMessage) error) []string {
	text := strings.TrimSpace(out)
	if text == "" {
		return nil
	}

	var warnings []string
	if strings.HasPrefix(text, "[") {
		var entries []json.RawMessage
		if err := json.Unmarshal([]byte(text), &entries); err != nil {
			return []string{"output is not a JSON array: " + err.Error()}
		}
		for i, raw := range entries {
			if err := visit(raw); err != nil {
				warnings = append(warnings, "entry "+strconv.Itoa(i+1)+": "+err.Error())
			}
		}
		return warnings
	}

	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "{") {
			warnings = append(warnings, "line "+strconv.Itoa(i+1)+": not a JSON object")
			continue
		}
		if err := visit(json.RawMessage(line)); err != nil {
			warnings = append(warnings, "line "+strconv.Itoa(i+1)+": "+err.Error())
		}
	}
	return warnings
}

// labelValue returns the first of the given labels that is set.
func labelValue(labels map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(labels[key]); value != "" {
			return value
		}
	}
	return ""
}

// splitList splits a comma-separated list, trimming and dropping empties.
func splitList(packed string) []string {
	var out []string
	for _, item := range strings.Split(packed, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// clean trims a value and maps docker's <none> placeholder to the empty string.
func clean(value string) string {
	value = strings.TrimSpace(value)
	if value == noneValue {
		return ""
	}
	return value
}

// cleanDigest keeps a digest only when it looks like one. Docker prints <none>
// for an image without one, and that must not reach the report as a digest.
func cleanDigest(value string) string {
	value = clean(value)
	if !strings.Contains(value, ":") {
		return ""
	}
	return value
}

// cutLast splits around the last occurrence of sep.
func cutLast(value, sep string) (before, after string, found bool) {
	idx := strings.LastIndex(value, sep)
	if idx < 0 {
		return value, "", false
	}
	return value[:idx], value[idx+len(sep):], true
}

// atoi parses a port, returning zero for anything that is not one.
func atoi(value string) int {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n < 0 {
		return 0
	}
	return n
}
