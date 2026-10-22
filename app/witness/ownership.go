package witness

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// Whose is this container? A port, a name or a volume that is "in use" means
// nothing until that is answered: the previous version of this very deployment is
// in the way of every redeployment, and Compose replaces it on purpose; a container
// of anybody else's is in the way for real. The answer comes from what Compose itself
// wrote on the container when it created it — the project, the service, the
// directory and files it was deployed from, whether it was a one-off `run`, and the
// configuration hash — read through the engine this audit inspected.

// ownerKind classifies an existing container against the planned run.
type ownerKind string

const (
	// ownService: this project, a service the plan starts. Compose recreates it
	// (or keeps it when its configuration is unchanged).
	ownService ownerKind = "this deployment"
	// ownOrphan: this project, a service the plan does not start. `up` leaves it
	// running unless --remove-orphans is given.
	ownOrphan ownerKind = "an orphan of this project"
	// ownOneOff: a `docker compose run` container of this project; `up` never
	// replaces it.
	ownOneOff ownerKind = "a one-off run of this project"
	// otherCheckout: the same project name, deployed from another directory. Compose
	// cannot tell the two apart and will take the other one's containers over.
	otherCheckout ownerKind = "another checkout using the same project name"
	// renamedProject: another project name, deployed from this plan's directory —
	// most likely this deployment under its previous name. Compose will not touch it.
	renamedProject ownerKind = "this directory under another project name"
	// foreignProject: another Compose project.
	foreignProject ownerKind = "another Compose project"
	// unmanaged: no Compose labels at all — created by `docker run` or a tool.
	unmanaged ownerKind = "no Compose project"
	// unlabelled: the engine reported no labels, so ownership cannot be read.
	unlabelled ownerKind = "unknown (the engine reported no labels)"
)

// ownership is what the plan does to one existing container.
type ownership struct {
	kind ownerKind
	// released is true when Compose stops or removes the container before it starts
	// the plan's containers — so whatever it holds (a port, a name) is free for them.
	released bool
	// action is what `up` does to it, in the change list's words.
	action string
}

// ownerOf classifies one existing container against the planned run.
func ownerOf(in Input, c model.Container) ownership {
	switch {
	case !c.Labelled && c.Project == "" && c.Service == "":
		return ownership{kind: unlabelled, action: "left as it is — whose it is could not be read"}
	case c.Project == "":
		return ownership{kind: unmanaged, action: "left as it is"}
	}

	same := sameProject(in, c.Project)
	sameDir := sameDirectory(in, c.WorkingDir)
	switch {
	case same && c.OneOff:
		return ownership{kind: ownOneOff, action: "left as it is: `up` never replaces a one-off run"}
	case same && differentDirectory(in, c.WorkingDir):
		return ownership{kind: otherCheckout, released: true,
			action: "taken over: it carries this project's name but was deployed from " + c.WorkingDir}
	case same && !plannedService(in, c.Service):
		if in.Plan != nil && in.Plan.RemoveOrphans {
			return ownership{kind: ownOrphan, released: true, action: "removed (--remove-orphans)"}
		}
		return ownership{kind: ownOrphan, action: "left running: its service is not in the plan, and without " +
			"--remove-orphans `up` does not remove it"}
	case same:
		return ownership{kind: ownService, released: true, action: composeAction(in, c)}
	case sameDir:
		return ownership{kind: renamedProject, action: "left as it is: `up` does not touch another project"}
	default:
		return ownership{kind: foreignProject, action: "left as it is"}
	}
}

// composeAction is what `up` does to an existing container of a planned service:
// keep it when its configuration is unchanged, recreate it otherwise — decided the
// way Compose decides, by the configuration hash.
func composeAction(in Input, c model.Container) string {
	if in.Plan == nil {
		return "replaced by the new version"
	}
	switch {
	case in.Plan.ForceRecreate:
		return "recreated (--force-recreate): stopped and removed, then created again"
	case in.Plan.NoRecreate:
		return "kept as it is (--no-recreate)" + startedSuffix(c)
	}
	want, known := in.Plan.ConfigHashes[c.Service]
	switch {
	case !known || c.ConfigHash == "":
		return "recreated if its configuration changed, kept otherwise — the configuration hashes could not be compared"
	case want == c.ConfigHash:
		return "kept: its configuration is unchanged" + startedSuffix(c)
	default:
		return "recreated: its configuration changed (config hash " + shortHash(c.ConfigHash) + " → " +
			shortHash(want) + "), so it is stopped and removed, then created again"
	}
}

func startedSuffix(c model.Container) string {
	if c.State != "" && c.State != "running" {
		return ", and started"
	}
	return ""
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// plannedService reports whether the plan starts a service of this name. A
// container whose service label is missing is given the benefit of the doubt.
func plannedService(in Input, service string) bool {
	if service == "" {
		return true
	}
	for _, svc := range in.Manifest.Services {
		if svc.Name == service {
			return true
		}
	}
	return false
}

func planDirectory(in Input) string {
	if in.Plan != nil {
		return in.Plan.ProjectDirectory
	}
	return ""
}

func sameDirectory(in Input, dir string) bool {
	plan := planDirectory(in)
	return plan != "" && dir != "" && filepath.Clean(plan) == filepath.Clean(dir)
}

func differentDirectory(in Input, dir string) bool {
	plan := planDirectory(in)
	return plan != "" && dir != "" && filepath.Clean(plan) != filepath.Clean(dir)
}

// describeOwner renders whose a container is, for a finding or a change row.
func describeOwner(in Input, c model.Container) string {
	switch o := ownerOf(in, c); o.kind {
	case ownService:
		return fmt.Sprintf("Compose project %q (this deployment)", c.Project)
	case ownOrphan:
		return fmt.Sprintf("Compose project %q, service %q, which the plan does not start (an orphan)", c.Project, c.Service)
	case ownOneOff:
		return fmt.Sprintf("Compose project %q, a one-off `docker compose run`", c.Project)
	case otherCheckout:
		return fmt.Sprintf("Compose project %q, deployed from another directory (%s)", c.Project, c.WorkingDir)
	case renamedProject:
		return fmt.Sprintf("Compose project %q, deployed from this plan's directory under another project name", c.Project)
	case foreignProject:
		return fmt.Sprintf("Compose project %q", c.Project)
	default:
		return string(o.kind)
	}
}

// 25. witness.project_ownership
//
// Containers that Compose ties to this deployment by name but that are not simply
// its previous version: another checkout using the same project name (which `up`
// will take over), this directory deployed under another name (which `up` leaves
// running), orphans the plan no longer starts, and containers whose labels could not
// be read.
func projectOwnership(in Input) []model.Finding {
	groups := map[ownerKind][]model.Container{}
	for _, c := range in.Caps.Containers {
		o := ownerOf(in, c)
		groups[o.kind] = append(groups[o.kind], c)
	}

	var out []model.Finding
	if list := groups[otherCheckout]; len(list) > 0 {
		out = append(out, ownershipFinding(in, list, model.OutcomeProblem, model.FindingWarning,
			fmt.Sprintf("Project %q is already deployed from another directory", in.Project),
			fmt.Sprintf("%d container(s) carry this deployment's project name %q but were created from %s, not from %s. "+
				"Compose identifies a deployment by its project name alone, so `up` here treats them as its own.",
				len(list), in.Project, workingDirs(list), planDirectory(in)),
			"The other deployment is stopped, recreated from this plan, or removed as an orphan — whoever runs it "+
				"loses it without warning, and the two checkouts keep overwriting each other.",
			"Deploy this checkout under its own --project-name, or stop the other deployment first if this one "+
				"is meant to replace it."))
	}
	if list := groups[renamedProject]; len(list) > 0 {
		out = append(out, ownershipFinding(in, list, model.OutcomeManualCheck, model.FindingInfo,
			"This directory is already deployed under another project name",
			fmt.Sprintf("%d container(s) were created from %s under project(s) %s, not %q. `up` under the new name "+
				"does not stop them.", len(list), planDirectory(in), projects(list), in.Project),
			"They keep running — and keep any port or name they hold, which the port and container-name checks "+
				"report — next to the new deployment.",
			"Decide whether the old project should go: `docker compose -p <old name> down`, or deploy with the old "+
				"--project-name."))
	}
	if list := groups[ownOrphan]; len(list) > 0 {
		out = append(out, ownershipFinding(in, list, model.OutcomeManualCheck, model.FindingInfo,
			fmt.Sprintf("%d container(s) of this project belong to no service of the plan", len(list)),
			fmt.Sprintf("Project %q has containers for service(s) %s, which the plan does not start. Without "+
				"--remove-orphans `up` leaves them running.", in.Project, services(list)),
			"An orphan keeps its ports, volumes and resources, and runs a version nobody deploys any more.",
			"Pass --remove-orphans to the deployment (and to this audit) if they should go, or keep the services "+
				"in the plan."))
	}
	if list := groups[unlabelled]; len(list) > 0 {
		out = append(out, ownershipFinding(in, list, model.OutcomeUnknown, model.FindingWarning,
			"Whose some containers are could not be established",
			fmt.Sprintf("The engine reported no labels for %d container(s), so whether they belong to this "+
				"deployment cannot be read.", len(list)),
			"A container of unknown ownership may be this deployment's previous version or something else; "+
				"the checks that depend on it cannot decide.",
			"Check by hand: `docker inspect --format '{{json .Config.Labels}}' <container>`."))
	}
	return out
}

func ownershipFinding(in Input, list []model.Container, outcome model.Outcome, severity model.FindingSeverity,
	title, description, why, todo string) model.Finding {
	var lines []string
	for _, c := range list {
		lines = append(lines, fmt.Sprintf("container %s: project %q, service %q, working_dir %q, state %s",
			c.Name, c.Project, c.Service, c.WorkingDir, c.State))
	}
	return model.Finding{
		Code:         "witness.project_ownership",
		Category:     model.CategoryConflict,
		Severity:     severity,
		Confidence:   model.ConfidenceHigh,
		Outcome:      outcome,
		Subject:      containerNames(list),
		Title:        title,
		Description:  description,
		WhyItMatters: why,
		WhatToDo:     todo,
		Evidence: []model.Evidence{
			evidence(in, engineCommand(in, "ps -a --format {{json .}}"), strings.Join(lines, "\n")),
		},
	}
}

func assessProjectOwnership(in Input) verdict {
	if listed, why := engineList(in, model.SourceContainers); !listed {
		return undecided(in, "the engine's containers could not be listed ("+why+"), so which existing "+
			"containers this deployment would replace is unknown", engineCommand(in, "ps -a --format {{json .}}"),
			why, engineTodo)
	}
	return checked("every existing container of project " + in.Project + " is this deployment's previous version, " +
		"or there is none")
}

func workingDirs(list []model.Container) string { return joinDistinct(list, func(c model.Container) string { return c.WorkingDir }) }
func projects(list []model.Container) string    { return joinDistinct(list, func(c model.Container) string { return fmt.Sprintf("%q", c.Project) }) }
func services(list []model.Container) string    { return joinDistinct(list, func(c model.Container) string { return c.Service }) }
func containerNames(list []model.Container) string {
	return joinDistinct(list, func(c model.Container) string { return c.Name })
}

func joinDistinct(list []model.Container, pick func(model.Container) string) string {
	var out []string
	for _, c := range list {
		if v := pick(c); v != "" && !contains(out, v) {
			out = append(out, v)
		}
	}
	return strings.Join(out, ", ")
}
