package targetresolve

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// registryManifestHit is one directory confirmed, via a valid server.json,
// to be an MCP server, independent of what implementation language it is.
type registryManifestHit struct {
	Dir  string
	Name string
	// NameConfirmed is true when Name came from the manifest's own "name"
	// field (a real, publishable registry identifier), false when Name is
	// the directory-basename fallback (registryManifestDisplayName), used
	// when the checked-in manifest still has an unsubstituted build-time
	// token. This distinction matters when a Project already exists at this
	// directory from a recognized ecosystem manifest (e.g. a Go module's
	// name derived from its module path): an unconfirmed fallback name
	// should not clobber a name that ecosystem-specific parsing already
	// derived meaningfully, but a real registry name should win.
	NameConfirmed bool

	// HasLocalPackages is true when the manifest's "packages" array is
	// non-empty -- i.e. there is at least one locally-buildable package
	// description, as opposed to only "remotes" (hosted elsewhere). See
	// describe for what a remotes-only manifest means.
	HasLocalPackages bool

	// Packages are the npm and PyPI packages the manifest says the server
	// is published as.
	Packages []registryPackage
}

// registryPackage is one package a registry manifest names.
type registryPackage struct {
	RegistryType string
	Identifier   string
}

// publishedBy reports whether project p is the source of pkg: a Node
// package of that name, or a Python project of that (normalized) name.
func (pkg registryPackage) publishedBy(p *Project) bool {
	switch pkg.RegistryType {
	case "npm":
		return p.Ecosystem == "node" && p.PackageName == pkg.Identifier
	case "pypi":
		return p.Ecosystem == "python" && p.PackageName != "" && normalizePEP503(p.PackageName) == normalizePEP503(pkg.Identifier)
	}
	return false
}

// publishingProject returns the one non-test project at or below the
// manifest's directory that publishes a package the manifest names, or nil
// when none or several do. A server.json at a monorepo's root typically
// names the one workspace package that is the server.
func (hit registryManifestHit) publishingProject(projects []*Project) *Project {
	var found *Project
	for _, p := range projects {
		if !within(p.Dir, hit.Dir) || isTestShapedProject(p) {
			continue
		}
		for _, pkg := range hit.Packages {
			if pkg.publishedBy(p) {
				if found != nil && found != p {
					return nil
				}
				found = p
			}
		}
	}
	return found
}

// isOwnershipBoundary reports whether a server.json in dir makes dir the
// ownership root of the projects below it: dir must hold a valid registry
// manifest of a locally built server (it has packages) that does not name
// a package published from another directory, since such a manifest
// describes that one project rather than everything below it.
func isOwnershipBoundary(dir string, projects []*Project) bool {
	hit, ok := readRegistryManifest(filepath.Join(dir, "server.json"))
	if !ok || !hit.HasLocalPackages {
		return false
	}
	described := hit.publishingProject(projects)
	return described == nil || filepath.Clean(described.Dir) == filepath.Clean(dir)
}

// isValidRegistryManifest applies a minimal structural check for the
// official MCP Registry server manifest schema
// (https://static.modelcontextprotocol.io/schemas/.../server.schema.json):
// a non-empty "name" plus a non-empty "packages" or "remotes" array. This
// guards against an unrelated file that merely happens to be named
// server.json -- a real MCP registry manifest always describes at least one
// way to obtain or reach the server.
func isValidRegistryManifest(doc map[string]interface{}) bool {
	name, hasName := doc["name"].(string)
	if !hasName || strings.TrimSpace(name) == "" {
		return false
	}
	if arr, ok := doc["packages"].([]interface{}); ok && len(arr) > 0 {
		return true
	}
	if arr, ok := doc["remotes"].([]interface{}); ok && len(arr) > 0 {
		return true
	}
	return false
}

// registryManifestDisplayName returns the manifest's own "name" field and
// true, or falls back to the containing directory's basename and false when
// the name is empty or looks like an unsubstituted build-time template
// token (e.g. "<<McpRepositoryName>>", seen verbatim in real, unbuilt
// checkouts that use MSBuild property substitution at publish time).
func registryManifestDisplayName(doc map[string]interface{}, dir string) (string, bool) {
	if name, ok := doc["name"].(string); ok {
		trimmed := strings.TrimSpace(name)
		if trimmed != "" && !strings.HasPrefix(trimmed, "<<") {
			return trimmed, true
		}
	}
	return filepath.Base(dir), false
}

// discoverRegistryManifests returns every valid server.json under repoRoot.
func discoverRegistryManifests(repoRoot string) ([]registryManifestHit, error) {
	var hits []registryManifestHit
	err := walkFiles(repoRoot, nil, func(path string, info os.FileInfo) error {
		if strings.ToLower(info.Name()) != "server.json" {
			return nil
		}
		if hit, ok := readRegistryManifest(path); ok {
			hits = append(hits, hit)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return hits, nil
}

// readRegistryManifest parses the server.json at path, reporting false when
// it is not a valid MCP registry manifest. A file merely named server.json
// is not one (isValidRegistryManifest).
func readRegistryManifest(path string) (registryManifestHit, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return registryManifestHit{}, false
	}
	dir := filepath.Dir(path)
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil || !isValidRegistryManifest(doc) {
		return registryManifestHit{}, false
	}
	name, confirmed := registryManifestDisplayName(doc, dir)
	hit := registryManifestHit{Dir: filepath.Clean(dir), Name: name, NameConfirmed: confirmed}
	packages, _ := doc["packages"].([]interface{})
	hit.HasLocalPackages = len(packages) > 0
	for _, value := range packages {
		pkg, _ := value.(map[string]interface{})
		registryType, _ := pkg["registryType"].(string)
		identifier, _ := pkg["identifier"].(string)
		if identifier = strings.TrimSpace(identifier); identifier != "" && !strings.HasPrefix(identifier, "<<") {
			hit.Packages = append(hit.Packages, registryPackage{RegistryType: registryType, Identifier: identifier})
		}
	}
	return hit, true
}

// applyRegistryManifestSignals applies the authoritative, language-agnostic
// signal: a directory with a valid server.json describes an MCP server,
// whatever the source heuristics in signals.go concluded. The manifest
// describes, in order of preference: the one project that publishes a
// package it names; the project in its own directory; its one non-test
// descendant project (server.json may sit directories above the manifest
// it describes, as in servers/Foo/server.json for
// servers/Foo/src/Foo.csproj). With none of those, a minimal Project is
// synthesized, so a server in a language without a manifest parser is
// still found. Ambiguity never upgrades a project: a server's own test
// project must never take its server.json.
func applyRegistryManifestSignals(repoRoot string, projects []*Project) ([]*Project, error) {
	hits, err := discoverRegistryManifests(repoRoot)
	if err != nil {
		return projects, err
	}
	byDir := make(map[string]*Project, len(projects))
	for _, p := range projects {
		byDir[filepath.Clean(p.Dir)] = p
	}

	for _, hit := range hits {
		if named := hit.publishingProject(projects); named != nil {
			note := ""
			if filepath.Clean(named.Dir) != hit.Dir {
				note = fmt.Sprintf(" (server.json at %s names this package)", repoRelative(repoRoot, hit.Dir))
			}
			hit.describe(named, note)
			continue
		}
		if existing, ok := byDir[hit.Dir]; ok {
			hit.describe(existing, "")
			continue
		}
		if candidate := findUnambiguousDescendantProject(hit.Dir, projects); candidate != nil {
			hit.describe(candidate, " (server.json found in an ancestor directory)")
			continue
		}

		synthesized := &Project{
			Name:      hit.Name,
			Dir:       hit.Dir,
			RelDir:    repoRelative(repoRoot, hit.Dir),
			Ecosystem: "unknown",
		}
		hit.describe(synthesized, "; no recognized ecosystem manifest found in this directory")
		projects = append(projects, synthesized)
		byDir[hit.Dir] = synthesized
	}

	return projects, nil
}

// describe applies the manifest to the project it describes. A manifest
// with a package confirms the project as a server. A remotes-only manifest
// makes the project a remote reference, unless its own source already shows
// it is a server: a local proxy or development build of a hosted server is
// still code to scan.
func (hit registryManifestHit) describe(p *Project, note string) {
	switch {
	case hit.HasLocalPackages:
		p.Role, p.RoleConfirmedByManifest = RoleMCPServer, true
		p.Evidence = append(p.Evidence, "confirmed as an MCP server by a server.json registry manifest"+note)
	case p.Role == RoleMCPServer:
		p.Evidence = append(p.Evidence, `server.json declares only remote endpoints ("remotes"); kept as a server for its own server code`+note)
	default:
		p.Role, p.RoleConfirmedByManifest = RoleRemoteReference, false
		p.Evidence = append(p.Evidence, `server.json declares only remote endpoints ("remotes"), no locally-buildable package -- classified as a remote reference rather than a local scan target`+note)
	}
	if hit.NameConfirmed {
		p.Name = hit.Name
	}
}

// findUnambiguousDescendantProject returns the single project strictly below
// hitDir that is not test-shaped, or nil when there are none or several.
func findUnambiguousDescendantProject(hitDir string, projects []*Project) *Project {
	var candidate *Project
	for _, p := range projects {
		pDir := filepath.Clean(p.Dir)
		if pDir == hitDir || !strings.HasPrefix(pDir, hitDir+string(filepath.Separator)) {
			continue
		}
		if isTestShapedProject(p) {
			continue
		}
		if candidate != nil {
			return nil // ambiguous: more than one non-test-shaped descendant
		}
		candidate = p
	}
	return candidate
}
