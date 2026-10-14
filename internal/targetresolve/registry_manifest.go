package targetresolve

import (
	"encoding/json"
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
	// description, as opposed to only "remotes" (hosted elsewhere, nothing
	// local to scan). A hit with HasLocalPackages == false resolves to
	// RoleRemoteReference instead of RoleMCPServer (see
	// applyRegistryManifestSignals).
	HasLocalPackages bool
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
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var doc map[string]interface{}
		if err := json.Unmarshal(data, &doc); err != nil || !isValidRegistryManifest(doc) {
			return nil
		}
		dir := filepath.Dir(path)
		name, confirmed := registryManifestDisplayName(doc, dir)
		packages, _ := doc["packages"].([]interface{})
		hits = append(hits, registryManifestHit{
			Dir:              dir,
			Name:             name,
			NameConfirmed:    confirmed,
			HasLocalPackages: len(packages) > 0,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return hits, nil
}

// applyRegistryManifestSignals applies the authoritative, language-agnostic
// signal: a directory with a valid server.json is an MCP server, whatever
// the source heuristics in signals.go concluded. It overrides the Role of
// the project in that directory (or of its one non-test descendant
// project), and synthesizes a minimal Project where there is none, so a
// server in a language without a manifest parser is still found.
func applyRegistryManifestSignals(repoRoot string, projects []*Project) ([]*Project, error) {
	hits, err := discoverRegistryManifests(repoRoot)
	if err != nil {
		return projects, err
	}
	if len(hits) == 0 {
		return projects, nil
	}

	byDir := make(map[string]*Project, len(projects))
	for _, p := range projects {
		byDir[filepath.Clean(p.Dir)] = p
	}

	const evidenceConfirmed = "confirmed as an MCP server by a server.json registry manifest"
	const evidenceRemoteOnly = `server.json declares only remote endpoints ("remotes"), no locally-buildable package -- classified as a remote reference rather than a local scan target`

	for _, hit := range hits {
		dir := filepath.Clean(hit.Dir)
		role := RoleMCPServer
		evidence := evidenceConfirmed
		roleConfirmed := true
		if !hit.HasLocalPackages {
			role = RoleRemoteReference
			evidence = evidenceRemoteOnly
			roleConfirmed = false
		}

		if existing, ok := byDir[dir]; ok {
			existing.Role = role
			existing.RoleConfirmedByManifest = roleConfirmed
			if hit.NameConfirmed {
				existing.Name = hit.Name
			}
			existing.Evidence = append(existing.Evidence, evidence)
			continue
		}

		// server.json may sit directories above the manifest it describes
		// (servers/Foo/server.json for servers/Foo/src/Foo.csproj), so the
		// one non-test-shaped project below it is upgraded rather than
		// duplicated. Zero or several candidates fall back to synthesizing
		// a project: an ambiguous match is not a safe upgrade, and a
		// server's own test project must never take its server.json.
		if candidate := findUnambiguousDescendantProject(dir, projects); candidate != nil {
			candidate.Role = role
			candidate.RoleConfirmedByManifest = roleConfirmed
			if hit.NameConfirmed {
				candidate.Name = hit.Name
			}
			candidate.Evidence = append(candidate.Evidence, evidence+" (server.json found in an ancestor directory)")
			continue
		}

		synthesized := &Project{
			Name:                    hit.Name,
			Dir:                     hit.Dir,
			RelDir:                  repoRelative(repoRoot, hit.Dir),
			Ecosystem:               "unknown",
			Role:                    role,
			RoleConfirmedByManifest: roleConfirmed,
			Evidence:                []string{evidence + "; no recognized ecosystem manifest found in this directory"},
		}
		projects = append(projects, synthesized)
		byDir[dir] = synthesized
	}

	return projects, nil
}

// findUnambiguousDescendantProject returns the single existing project
// whose directory is a strict descendant of hitDir, excluding test-shaped
// projects (isTestShapedProject, signals.go) as candidates. Returns nil if
// there are zero or more than one such candidate -- an ambiguous match is
// not a safe upgrade, and the caller falls back to synthesizing instead.
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
