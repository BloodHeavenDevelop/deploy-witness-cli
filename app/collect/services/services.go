// Package services enumerates service units from whichever init system the host
// runs.
package services

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
)

// Collect lists services. By default only the running ones are reported, which
// is what an audit asks for; includeInactive widens it to every known unit.
func Collect(runner *run.Runner, includeInactive bool, result *model.SectionResult) []model.Service {
	switch {
	case run.Available("systemctl"):
		return collectSystemd(runner, includeInactive, result)
	case run.Available("rc-status"):
		return collectOpenRC(runner, result)
	case run.Available("service"):
		return collectSysV(runner, result)
	default:
		result.Degrade("no init system tooling found (systemctl, rc-status, service); falling back to the process table")
		return collectProcesses(result)
	}
}

// ---------------------------------------------------------------- systemd

func collectSystemd(runner *run.Runner, includeInactive bool, result *model.SectionResult) []model.Service {
	// Exit 1 with output is normal when some unit is in a failed state.
	out, _, err := runner.OutputAllowExit([]int{1}, "systemctl", "list-units",
		"--type=service", "--all", "--no-pager", "--plain", "--no-legend")
	if err != nil {
		result.Fail("systemctl list-units: " + err.Error())
		return nil
	}

	enabled := unitFileStates(runner)

	var found []model.Service
	for _, line := range run.Lines(out) {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		name, load, active, sub := fields[0], fields[1], fields[2], fields[3]
		if !includeInactive && active != "active" {
			continue
		}

		found = append(found, model.Service{
			Name:        name,
			Description: strings.Join(fields[4:], " "),
			Load:        load,
			Active:      active,
			Sub:         sub,
			Enabled:     enabled[name],
			Manager:     "systemd",
		})
	}

	enrichSystemd(runner, found, result)

	sort.SliceStable(found, func(i, j int) bool { return found[i].Name < found[j].Name })
	return found
}

// unitFileStates maps a unit to enabled/disabled/masked/static. It comes from a
// separate command because list-units reports runtime state only — a service can
// be running now and disabled at boot, and that difference is the point of the
// column.
func unitFileStates(runner *run.Runner) map[string]string {
	states := map[string]string{}

	out, _, err := runner.OutputAllowExit([]int{1}, "systemctl", "list-unit-files",
		"--type=service", "--no-pager", "--plain", "--no-legend")
	if err != nil {
		return states
	}
	for _, line := range run.Lines(out) {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			states[fields[0]] = fields[1]
		}
	}
	return states
}

// showChunk bounds how many units one `systemctl show` invocation covers, so the
// argument list stays well inside ARG_MAX on hosts with thousands of units.
const showChunk = 100

func enrichSystemd(runner *run.Runner, found []model.Service, result *model.SectionResult) {
	index := map[string]*model.Service{}
	var names []string
	for i := range found {
		index[found[i].Name] = &found[i]
		names = append(names, found[i].Name)
	}

	for start := 0; start < len(names); start += showChunk {
		end := min(start+showChunk, len(names))

		args := append([]string{"show",
			"--property=Id",
			"--property=MainPID",
			"--property=User",
			"--property=ActiveEnterTimestamp",
		}, names[start:end]...)

		out, _, err := runner.OutputAllowExit([]int{1}, "systemctl", args...)
		if err != nil {
			result.Degrade("systemctl show: " + err.Error())
			return
		}

		for _, block := range strings.Split(out, "\n\n") {
			properties := map[string]string{}
			for _, line := range run.Lines(block) {
				key, value, ok := strings.Cut(line, "=")
				if ok {
					properties[key] = value
				}
			}
			service, ok := index[properties["Id"]]
			if !ok {
				continue
			}
			if pid, err := strconv.Atoi(properties["MainPID"]); err == nil && pid > 0 {
				service.MainPid = pid
			}
			// systemd reports an empty User for units running as root.
			service.User = properties["User"]
			if service.User == "" {
				service.User = "root"
			}
			service.Since = normaliseTimestamp(properties["ActiveEnterTimestamp"])
		}
	}
}

// normaliseTimestamp converts systemd's local-time stamp to the UTC ISO form the
// rest of the report uses. An unparseable value is passed through rather than
// dropped — a timestamp we cannot convert is still evidence.
func normaliseTimestamp(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "n/a" {
		return ""
	}
	for _, layout := range []string{
		"Mon 2006-01-02 15:04:05 MST",
		"Mon 2006-01-02 15:04:05 -0700",
		"2006-01-02 15:04:05 MST",
	} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC().Format("2006-01-02 15:04:05") + " UTC"
		}
	}
	return raw
}

// ---------------------------------------------------------------- OpenRC

func collectOpenRC(runner *run.Runner, result *model.SectionResult) []model.Service {
	out, _, err := runner.OutputAllowExit([]int{1}, "rc-status", "--all")
	if err != nil {
		result.Fail("rc-status: " + err.Error())
		return nil
	}

	var found []model.Service
	runlevel := ""
	for _, line := range run.Lines(out) {
		if strings.HasPrefix(line, "Runlevel:") {
			runlevel = strings.TrimSpace(strings.TrimPrefix(line, "Runlevel:"))
			continue
		}
		// "  sshd    [  started  ]"
		name, status, ok := strings.Cut(line, "[")
		if !ok {
			continue
		}
		found = append(found, model.Service{
			Name:        strings.TrimSpace(name),
			Active:      strings.TrimSpace(strings.Trim(status, "[] ")),
			Enabled:     runlevel,
			Description: "runlevel " + runlevel,
			Manager:     "openrc",
		})
	}
	return found
}

// ---------------------------------------------------------------- SysV

func collectSysV(runner *run.Runner, result *model.SectionResult) []model.Service {
	out, _, err := runner.OutputAllowExit([]int{1}, "service", "--status-all")
	if err != nil {
		result.Fail("service --status-all: " + err.Error())
		return nil
	}

	var found []model.Service
	for _, line := range run.Lines(out) {
		// " [ + ]  ssh"
		open, rest, ok := strings.Cut(line, "]")
		if !ok {
			continue
		}
		marker := strings.TrimSpace(strings.Trim(open, "[ "))
		active := map[string]string{"+": "active", "-": "inactive", "?": "unknown"}[marker]
		if active == "" {
			active = "unknown"
		}
		found = append(found, model.Service{
			Name:    strings.TrimSpace(rest),
			Active:  active,
			Manager: "sysv",
		})
	}
	return found
}

// ---------------------------------------------------------------- processes

// collectProcesses is the floor: on a host with no init tooling at all, the
// running long-lived processes are still worth listing. They are labelled
// `manager=process-table` so nobody mistakes them for managed units.
func collectProcesses(result *model.SectionResult) []model.Service {
	entries, err := readProcessTable()
	if err != nil {
		result.Fail("process table: " + err.Error())
		return nil
	}

	var found []model.Service
	for _, p := range entries {
		if p.ppid != 1 || p.pid == 1 {
			continue
		}
		found = append(found, model.Service{
			Name:        p.name,
			Description: p.cmdline,
			Active:      "running",
			MainPid:     p.pid,
			Manager:     "process-table",
		})
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].Name < found[j].Name })
	return found
}
