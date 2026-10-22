package audit

import (
	"errors"
	"strings"
	"testing"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

func TestComposeConfigArgsKeepThePlansOrder(t *testing.T) {
	plan := &model.LaunchPlan{
		ProjectDirectory: "/srv/app",
		Files:            []string{"/srv/app/compose.yml", "/srv/app/compose.prod.yml"},
		EnvFiles:         []string{"/srv/app/.env.prod"},
		Profiles:         []string{"web", "jobs"},
		ProjectName:      "shop",
	}
	got := strings.Join(composeConfigArgs(plan, true), " ")
	want := "compose --project-directory /srv/app --file /srv/app/compose.yml --file /srv/app/compose.prod.yml " +
		"--env-file /srv/app/.env.prod --profile web --profile jobs --project-name shop config --format json " +
		"--no-env-resolution"
	if got != want {
		t.Errorf("args =\n%s\nwant\n%s", got, want)
	}
}

func TestSelectServicesFollowsDependencies(t *testing.T) {
	parsed := &model.Manifest{Services: []model.ManifestService{
		{Name: "web", DependsOn: []string{"api"}}, {Name: "api", DependsOn: []string{"db"}},
		{Name: "db"}, {Name: "worker"},
	}}
	plan := &model.LaunchPlan{Services: []string{"web"}}
	if err := selectServices(plan, parsed); err != nil {
		t.Fatal(err)
	}
	if strings.Join(plan.Started, ",") != "api,db,web" || len(parsed.Services) != 3 {
		t.Errorf("started %v, kept %d", plan.Started, len(parsed.Services))
	}

	err := selectServices(&model.LaunchPlan{Services: []string{"ghost"}}, &model.Manifest{})
	if !errors.Is(err, errPlan) || !strings.Contains(err.Error(), "not in the resolved plan") {
		t.Errorf("unknown service: %v", err)
	}
}

func TestPlanProjectNamePrecedence(t *testing.T) {
	t.Setenv("COMPOSE_PROJECT_NAME", "")
	plan := &model.LaunchPlan{ProjectDirectory: "/srv/My App", Resolver: model.ResolverBuiltin}
	if name, source := planProjectName("", plan, &model.Manifest{}); name != "myapp" || source != "the project directory" {
		t.Errorf("directory: %s from %s", name, source)
	}
	if name, source := planProjectName("Shop", plan, &model.Manifest{}); name != "shop" || source != "--project-name" {
		t.Errorf("flag: %s from %s", name, source)
	}
	t.Setenv("COMPOSE_PROJECT_NAME", "fromenv")
	if name, source := planProjectName("", plan, &model.Manifest{}); name != "fromenv" || source != "COMPOSE_PROJECT_NAME" {
		t.Errorf("env: %s from %s", name, source)
	}
	compose := &model.LaunchPlan{ProjectDirectory: "/srv/app", Resolver: model.ResolverCompose}
	t.Setenv("COMPOSE_PROJECT_NAME", "")
	if name, _ := planProjectName("", compose, &model.Manifest{Name: "resolved"}); name != "resolved" {
		t.Errorf("Compose's own resolution must win: %s", name)
	}
}

func TestComposeEnvironmentNamesOnly(t *testing.T) {
	got := composeEnvironment([]string{"COMPOSE_PROFILES=web", "DOCKER_HOST=unix:///run/docker.sock",
		"HOME=/root", "COMPOSE_FILE=", "SECRET=x"})
	if strings.Join(got, ",") != "COMPOSE_PROFILES,DOCKER_HOST" {
		t.Errorf("environment = %v", got)
	}
}
