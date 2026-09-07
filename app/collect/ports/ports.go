// Package ports enumerates listening sockets.
package ports

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
)

// procNetFiles are the socket tables, paired with the protocol label they get in
// the report.
var procNetFiles = []struct{ path, protocol string }{
	{"/proc/net/tcp", "tcp"},
	{"/proc/net/tcp6", "tcp6"},
	{"/proc/net/udp", "udp"},
	{"/proc/net/udp6", "udp6"},
}

// TCP socket states as the kernel writes them in /proc/net/tcp.
const (
	tcpStateListen = "0A"
	tcpStateClose  = "07" // what an unconnected UDP socket reports
)

// Collect lists every listening socket with the process behind it.
//
// The kernel tables are read directly rather than shelling out to `ss` or
// `netstat`: neither is installed on a minimal image, and both would have to be
// present on the audited host — which is the one place a security audit should
// not be adding dependencies.
func Collect(runner *run.Runner, result *model.SectionResult) []model.Port {
	owners, restricted := processIndex()
	if restricted > 0 {
		result.Degrade(fmt.Sprintf(
			"%d processes were not readable, so some sockets have no owning process (run as root for full attribution)",
			restricted))
	}

	users := passwdIndex()

	var found []model.Port
	readable := 0

	for _, table := range procNetFiles {
		raw, err := os.ReadFile(table.path)
		if err != nil {
			result.Degrade(table.path + ": " + err.Error())
			continue
		}
		readable++
		found = append(found, parseTable(string(raw), table.protocol, owners, users)...)
	}

	if readable == 0 {
		result.Fail("no socket table under /proc/net was readable")
		return fallbackToSS(runner, result)
	}

	sort.SliceStable(found, func(i, j int) bool {
		if found[i].Port != found[j].Port {
			return found[i].Port < found[j].Port
		}
		return found[i].Protocol < found[j].Protocol
	})
	return found
}

func parseTable(content, protocol string, owners map[string]processInfo, users map[string]string) []model.Port {
	var out []model.Port

	lines := strings.Split(content, "\n")
	if len(lines) < 2 {
		return nil
	}

	for _, line := range lines[1:] { // the first line is the column header
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		local, remote, state, inode := fields[1], fields[2], fields[3], fields[9]

		if strings.HasPrefix(protocol, "tcp") {
			if state != tcpStateListen {
				continue
			}
		} else {
			// A UDP socket with a remote peer is a client, not a listener.
			if state != tcpStateClose || !isUnspecifiedEndpoint(remote) {
				continue
			}
		}

		ip, port, err := parseEndpoint(local)
		if err != nil {
			continue
		}

		entry := model.Port{
			Protocol: protocol,
			Address:  ip.String(),
			Port:     port,
			Exposure: classify(ip),
			State:    map[bool]string{true: "LISTEN", false: "OPEN"}[strings.HasPrefix(protocol, "tcp")],
		}
		if owner, ok := owners[inode]; ok {
			entry.Pid = owner.pid
			entry.Process = owner.name
			entry.Command = owner.cmdline
			entry.User = users[owner.uid]
			if entry.User == "" {
				entry.User = owner.uid
			}
		}
		out = append(out, entry)
	}
	return out
}

// classify says how far a bound address reaches. This is the column that turns a
// socket list into an audit: a database on 127.0.0.1 and the same database on
// 0.0.0.0 are the same service and completely different exposures.
func classify(ip net.IP) string {
	switch {
	case ip.IsLoopback():
		return model.ExposureLoopback
	case ip.IsUnspecified():
		return model.ExposureAll
	default:
		return model.ExposureInterface
	}
}

func isUnspecifiedEndpoint(endpoint string) bool {
	ip, port, err := parseEndpoint(endpoint)
	if err != nil {
		return false
	}
	return port == 0 && ip.IsUnspecified()
}

// parseEndpoint decodes the "ADDRESS:PORT" pairs in /proc/net/*.
//
// The address is hex, and each 32-bit word is in host byte order — little-endian
// on every platform this runs on — while the port is big-endian. Decoding both
// the same way is the classic way to end up reporting 1.0.0.127.
func parseEndpoint(endpoint string) (net.IP, int, error) {
	addrHex, portHex, found := strings.Cut(endpoint, ":")
	if !found {
		return nil, 0, fmt.Errorf("malformed endpoint %q", endpoint)
	}

	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return nil, 0, err
	}

	raw, err := hex.DecodeString(addrHex)
	if err != nil {
		return nil, 0, err
	}
	if len(raw)%4 != 0 || len(raw) == 0 {
		return nil, 0, fmt.Errorf("malformed address %q", addrHex)
	}

	ip := make(net.IP, len(raw))
	for word := 0; word < len(raw); word += 4 {
		for i := 0; i < 4; i++ {
			ip[word+i] = raw[word+3-i]
		}
	}
	return ip, int(port), nil
}

// ---------------------------------------------------------------- ownership

type processInfo struct {
	pid     int
	name    string
	cmdline string
	uid     string
}

// processIndex maps socket inodes to the process holding them, and reports how
// many processes it could not inspect.
func processIndex() (map[string]processInfo, int) {
	index := map[string]processInfo{}
	restricted := 0

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return index, restricted
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			// A process that exited between the listing and this read is not a
			// permission problem, and must not be counted as one.
			if os.IsPermission(err) {
				restricted++
			}
			continue
		}

		var info *processInfo
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			inode, ok := socketInode(link)
			if !ok {
				continue
			}
			if info == nil {
				info = describeProcess(pid)
			}
			if _, exists := index[inode]; !exists {
				index[inode] = *info
			}
		}
	}
	return index, restricted
}

func socketInode(link string) (string, bool) {
	const prefix = "socket:["
	if !strings.HasPrefix(link, prefix) || !strings.HasSuffix(link, "]") {
		return "", false
	}
	return link[len(prefix) : len(link)-1], true
}

func describeProcess(pid int) *processInfo {
	base := filepath.Join("/proc", strconv.Itoa(pid))
	info := &processInfo{pid: pid}

	if raw, err := os.ReadFile(filepath.Join(base, "comm")); err == nil {
		info.name = strings.TrimSpace(string(raw))
	}
	if raw, err := os.ReadFile(filepath.Join(base, "cmdline")); err == nil {
		parts := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		info.cmdline = strings.Join(parts, " ")
		if len(info.cmdline) > 200 {
			info.cmdline = info.cmdline[:200] + "…"
		}
	}
	if raw, err := os.ReadFile(filepath.Join(base, "status")); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(line, "Uid:") {
				continue
			}
			if fields := strings.Fields(line); len(fields) >= 2 {
				info.uid = fields[1] // the real UID
			}
			break
		}
	}
	return info
}

func passwdIndex() map[string]string {
	index := map[string]string{}
	raw, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return index
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		index[fields[2]] = fields[0]
	}
	return index
}

// ---------------------------------------------------------------- fallback

// fallbackToSS is the last resort for hosts where /proc/net is hidden (a
// hardened container with hidepid, for instance).
func fallbackToSS(runner *run.Runner, result *model.SectionResult) []model.Port {
	out, err := runner.Output("ss", "-lntupH")
	if err != nil {
		result.Note("ss is unavailable as well: " + err.Error())
		return nil
	}

	var found []model.Port
	for _, line := range run.Lines(out) {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		protocol, local := fields[0], fields[4]

		i := strings.LastIndex(local, ":")
		if i < 0 {
			continue
		}
		port, err := strconv.Atoi(local[i+1:])
		if err != nil {
			continue
		}
		address := strings.Trim(local[:i], "[]")
		ip := net.ParseIP(address)
		// A wildcard, or an address `ss` printed in a form net.ParseIP will not
		// take, means every interface. Guessing "one interface" from an
		// unparseable address would understate the exposure, which is the wrong
		// direction to be wrong in.
		exposure := model.ExposureAll
		if address != "*" && ip != nil {
			exposure = classify(ip)
		}

		found = append(found, model.Port{
			Protocol: protocol,
			Address:  address,
			Port:     port,
			Exposure: exposure,
			State:    fields[1],
			Command:  strings.Join(fields[5:], " "),
		})
	}
	result.Note("socket list came from `ss`, so process attribution is approximate")
	return found
}
