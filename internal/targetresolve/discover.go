package targetresolve

import (
	"os"
	"path/filepath"
	"strings"

	"mcpxray/internal/reposcan"
)

// manifestConstructors maps a manifest basename to the ecosystem-specific
// constructor that turns it into a Project. Ecosystems whose manifest
// filename is fixed (go.mod, package.json, pyproject.toml, pom.xml,
// Cargo.toml) are matched here by exact name. .csproj is handled separately
// in discoverProjects below (see newDotnetProject) because its filename
// varies per project (e.g. Fabric.Mcp.Server.csproj), so it can't be a map
// key. newRustProject can return (nil, nil) for a Cargo.toml that declares
// no [package] (a virtual workspace-root manifest) -- already tolerated by
// the `if project != nil` check below, same as any other constructor.
var manifestConstructors = map[string]func(manifestPath string) (*Project, error){
	"go.mod":         newGoProject,
	"package.json":   newNodeProject,
	"pyproject.toml": newPythonProject,
	"pom.xml":        newJavaProject,
	"Cargo.toml":     newRustProject,
}

// discoverProjects returns one Project per ecosystem manifest under
// repoRoot, with Role left unset: classification needs every project, so it
// runs as a separate pass. A directory can hold several projects (say, a
// Python package inside a Node monorepo), so a manifest never stops the walk
// from descending further. A malformed manifest is skipped, not fatal.
func discoverProjects(repoRoot string) ([]*Project, error) {
	var projects []*Project
	err := walkFiles(repoRoot, nil, func(path string, info os.FileInfo) error {
		constructor, ok := manifestConstructors[info.Name()]
		if !ok {
			if !strings.HasSuffix(info.Name(), ".csproj") {
				return nil
			}
			constructor = newDotnetProject
		}
		project, err := constructor(path)
		if err != nil || project == nil {
			return nil
		}
		project.RelDir = repoRelative(repoRoot, project.Dir)
		projects = append(projects, project)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return projects, nil
}

// walkFiles calls visit for every file under root, skipping the directories
// the scanners skip by default (reposcan.DefaultExcludedDirs) and any
// directory skipDir reports (nil skips none). Unreadable entries are
// skipped rather than aborting the walk; visit may return filepath.SkipAll
// to stop early.
func walkFiles(root string, skipDir func(dir string) bool, visit func(path string, info os.FileInfo) error) error {
	prune := &reposcan.Config{Root: root, ExcludedPaths: reposcan.DefaultExcludedDirs()}
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		switch {
		case err != nil:
			return nil
		case info.IsDir():
			if prune.ShouldExclude(path) || (skipDir != nil && skipDir(path)) {
				return filepath.SkipDir
			}
			return nil
		case prune.ShouldExclude(path):
			return nil
		}
		return visit(path, info)
	})
}
