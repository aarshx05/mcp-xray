package targetresolve

import (
	"path/filepath"
	"testing"
)

func TestNewPythonProject_PEP621Name(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "pyproject.toml")
	writeFile(t, manifest, "[project]\nname = \"my-py-server\"\n")

	p, err := newPythonProject(manifest)
	if err != nil {
		t.Fatalf("newPythonProject returned error: %v", err)
	}
	if p.Name != "my-py-server" {
		t.Errorf("expected name 'my-py-server', got %q", p.Name)
	}
}

func TestNewPythonProject_PoetryNameFallback(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "pyproject.toml")
	writeFile(t, manifest, "[tool.poetry]\nname = \"poetry-server\"\n")

	p, err := newPythonProject(manifest)
	if err != nil {
		t.Fatalf("newPythonProject returned error: %v", err)
	}
	if p.Name != "poetry-server" {
		t.Errorf("expected name 'poetry-server', got %q", p.Name)
	}
}

func TestResolvePythonLocalDeps_PoetryPathDependency(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "server")
	sharedDir := filepath.Join(root, "shared")

	writeFile(t, filepath.Join(serverDir, "pyproject.toml"), `[tool.poetry]
name = "server"

[tool.poetry.dependencies]
python = "^3.10"
shared-lib = { path = "../shared", develop = true }
`)
	writeFile(t, filepath.Join(sharedDir, "pyproject.toml"), "[tool.poetry]\nname = \"shared-lib\"\n")

	server, err := newPythonProject(filepath.Join(serverDir, "pyproject.toml"))
	if err != nil {
		t.Fatalf("newPythonProject(server) error: %v", err)
	}
	shared, err := newPythonProject(filepath.Join(sharedDir, "pyproject.toml"))
	if err != nil {
		t.Fatalf("newPythonProject(shared) error: %v", err)
	}
	resolvePythonLocalDeps([]*Project{server, shared})

	if len(server.LocalDeps) != 1 || server.LocalDeps[0] != shared.Dir {
		t.Errorf("expected server.LocalDeps == [%q], got %v", shared.Dir, server.LocalDeps)
	}
	if len(server.DevLocalDeps) != 0 {
		t.Errorf("a [tool.poetry.dependencies] dependency is needed at run time, got DevLocalDeps %v", server.DevLocalDeps)
	}
}

func TestResolvePythonLocalDeps_UvSourcesPath(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "server")
	sharedDir := filepath.Join(root, "shared")

	writeFile(t, filepath.Join(serverDir, "pyproject.toml"), `[project]
name = "server"
dependencies = ["shared-lib"]

[tool.uv.sources]
shared-lib = { path = "../shared" }
`)
	writeFile(t, filepath.Join(sharedDir, "pyproject.toml"), "[project]\nname = \"shared-lib\"\n")

	server, _ := newPythonProject(filepath.Join(serverDir, "pyproject.toml"))
	shared, _ := newPythonProject(filepath.Join(sharedDir, "pyproject.toml"))
	resolvePythonLocalDeps([]*Project{server, shared})

	if len(server.LocalDeps) != 1 || server.LocalDeps[0] != shared.Dir {
		t.Errorf("expected server.LocalDeps == [%q], got %v", shared.Dir, server.LocalDeps)
	}
}

func TestResolvePythonLocalDeps_UvSourcesWorkspaceTrue(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "server")
	sharedDir := filepath.Join(root, "shared")

	writeFile(t, filepath.Join(serverDir, "pyproject.toml"), `[project]
name = "server"
dependencies = ["shared-lib"]

[tool.uv.sources]
shared-lib = { workspace = true }
`)
	writeFile(t, filepath.Join(sharedDir, "pyproject.toml"), "[project]\nname = \"shared-lib\"\n")

	server, _ := newPythonProject(filepath.Join(serverDir, "pyproject.toml"))
	shared, _ := newPythonProject(filepath.Join(sharedDir, "pyproject.toml"))
	resolvePythonLocalDeps([]*Project{server, shared})

	if len(server.LocalDeps) != 1 || server.LocalDeps[0] != shared.Dir {
		t.Errorf("expected server.LocalDeps == [%q] via workspace=true name match, got %v", shared.Dir, server.LocalDeps)
	}
}

// A uv workspace member listed only in a dependency group is a development
// dependency; one in [project].dependencies is needed at run time.
func TestResolvePythonLocalDeps_DependencyGroupsAreDevelopmentOnly(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pyproject.toml"), `
[project]
name = "sdk"
dependencies = ["helpers"]

[dependency-groups]
dev = ["examples"]

[tool.uv.sources]
helpers = { workspace = true }
examples = { workspace = true }
`)
	writeFile(t, filepath.Join(root, "helpers", "pyproject.toml"), "[project]\nname = \"helpers\"\n")
	writeFile(t, filepath.Join(root, "examples", "pyproject.toml"), "[project]\nname = \"examples\"\n")
	var projects []*Project
	for _, dir := range []string{root, filepath.Join(root, "helpers"), filepath.Join(root, "examples")} {
		p, err := newPythonProject(filepath.Join(dir, "pyproject.toml"))
		if err != nil {
			t.Fatal(err)
		}
		projects = append(projects, p)
	}

	resolvePythonLocalDeps(projects)

	sdk := projects[0]
	if len(sdk.LocalDeps) != 2 {
		t.Fatalf("LocalDeps = %v, want helpers and examples", sdk.LocalDeps)
	}
	if len(sdk.DevLocalDeps) != 1 || sdk.DevLocalDeps[0] != filepath.Join(root, "examples") {
		t.Errorf("DevLocalDeps = %v, want only examples", sdk.DevLocalDeps)
	}
}

// Poetry groups are development only, also for a PEP 621 project with no
// [tool.poetry.dependencies], while a dependency the project needs at run
// time stays a runtime one when a group repeats it.
func TestResolvePythonLocalDeps_PoetryGroupsAreDevelopmentOnly(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pyproject.toml"), `
[project]
name = "app"
dependencies = ["core"]

[tool.poetry.group.dev.dependencies]
core = { path = "core", develop = true }
fixtures = { path = "fixtures" }
`)
	writeFile(t, filepath.Join(root, "core", "pyproject.toml"), "[project]\nname = \"core\"\n")
	writeFile(t, filepath.Join(root, "fixtures", "pyproject.toml"), "[project]\nname = \"fixtures\"\n")
	var projects []*Project
	for _, dir := range []string{root, filepath.Join(root, "core"), filepath.Join(root, "fixtures")} {
		p, err := newPythonProject(filepath.Join(dir, "pyproject.toml"))
		if err != nil {
			t.Fatal(err)
		}
		projects = append(projects, p)
	}

	resolvePythonLocalDeps(projects)

	app := projects[0]
	if len(app.LocalDeps) != 2 {
		t.Fatalf("LocalDeps = %v, want core and fixtures", app.LocalDeps)
	}
	if len(app.DevLocalDeps) != 1 || app.DevLocalDeps[0] != filepath.Join(root, "fixtures") {
		t.Errorf("DevLocalDeps = %v, want only fixtures", app.DevLocalDeps)
	}
}
