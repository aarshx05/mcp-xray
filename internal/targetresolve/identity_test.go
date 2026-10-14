package targetresolve

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHasOwnershipBoundary_ValidServerJSON(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "server.json"), validServerJSON)
	if !hasOwnershipBoundary(dir) {
		t.Error("expected a valid server.json to be recognized as an ownership boundary")
	}
}

func TestHasOwnershipBoundary_UnrelatedFileNamedServerJSON(t *testing.T) {
	// Reproduces the reported flaw directly: hasOwnershipBoundary used to
	// only check that a file NAMED server.json existed, never that it was
	// actually a valid MCP registry manifest.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "server.json"), `{"port": 8080, "host": "localhost"}`)
	if hasOwnershipBoundary(dir) {
		t.Error("expected an unrelated file merely named server.json to NOT be an ownership boundary")
	}
}

func TestHasOwnershipBoundary_BlankNameServerJSON(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "server.json"), `{"name": "", "packages": [{"registryType": "npm", "identifier": "x"}]}`)
	if hasOwnershipBoundary(dir) {
		t.Error("expected a blank-name server.json to NOT be an ownership boundary")
	}
}

func TestHasOwnershipBoundary_ComponentJSONAloneIsNotABoundary(t *testing.T) {
	// component.json is the legacy Bower package manifest filename, unrelated
	// to MCP and common enough in older JavaScript repos that treating it as
	// an ownership boundary risked false positives. It is deliberately not
	// checked at all any more.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "component.json"), `{"name": "some-bower-package"}`)
	if hasOwnershipBoundary(dir) {
		t.Error("expected component.json alone to NOT be an ownership boundary")
	}
}

func TestHasOwnershipBoundary_NoFile(t *testing.T) {
	dir := t.TempDir()
	if hasOwnershipBoundary(dir) {
		t.Error("expected a directory with neither file to NOT be an ownership boundary")
	}
}

func TestHasOwnershipBoundary_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "server.json"), `{not valid json`)
	if hasOwnershipBoundary(dir) {
		t.Error("expected malformed JSON to NOT be an ownership boundary")
	}
}

// TestAssignIdentities_UnrelatedServerJSONDoesNotMergeIndependentServers is
// the end-to-end reproduction of the reported consequence: two independent
// projects nested under a common ancestor that happens to contain an
// unrelated file named server.json must keep separate ComponentIDs (and,
// downstream in buildTargets/mergeTargetsByComponent, remain two separate
// targets) rather than being silently collapsed into one because the old
// hasOwnershipBoundary treated any server.json as authoritative.
func TestAssignIdentities_UnrelatedServerJSONDoesNotMergeIndependentServers(t *testing.T) {
	root := t.TempDir()
	platformDir := filepath.Join(root, "platform")
	writeFile(t, filepath.Join(platformDir, "server.json"), `{"unrelated": "config"}`)

	serverADir := filepath.Join(platformDir, "server-a")
	serverBDir := filepath.Join(platformDir, "server-b")
	if err := os.MkdirAll(serverADir, 0o755); err != nil {
		t.Fatalf("MkdirAll(server-a) failed: %v", err)
	}
	if err := os.MkdirAll(serverBDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(server-b) failed: %v", err)
	}

	serverA := &Project{Name: "server-a", Dir: serverADir, Ecosystem: "node", Role: RoleMCPServer}
	serverB := &Project{Name: "server-b", Dir: serverBDir, Ecosystem: "node", Role: RoleMCPServer}

	assignIdentities(root, []*Project{serverA, serverB})

	if serverA.ComponentID == serverB.ComponentID {
		t.Errorf("expected server-a and server-b to have distinct ComponentIDs (the unrelated platform/server.json must not merge them), got the same ComponentID %q for both", serverA.ComponentID)
	}
	if serverA.OwnershipRoot != filepath.Clean(serverADir) {
		t.Errorf("expected server-a's ownership root to remain its own directory, got %q", serverA.OwnershipRoot)
	}
	if serverB.OwnershipRoot != filepath.Clean(serverBDir) {
		t.Errorf("expected server-b's ownership root to remain its own directory, got %q", serverB.OwnershipRoot)
	}
}

// TestAssignIdentities_ValidServerJSONStillMergesSiblingProjects is the
// regression check for the case hasOwnershipBoundary is actually meant to
// handle: a REAL registry manifest one directory above two projects that
// belong together (e.g. a .NET server and a client packaged alongside it)
// must still merge them into one component.
func TestAssignIdentities_ValidServerJSONStillMergesSiblingProjects(t *testing.T) {
	root := t.TempDir()
	componentDir := filepath.Join(root, "my-component")
	writeFile(t, filepath.Join(componentDir, "server.json"), validServerJSON)

	serverDir := filepath.Join(componentDir, "server")
	if err := os.MkdirAll(serverDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(server) failed: %v", err)
	}

	server := &Project{Name: "server", Dir: serverDir, Ecosystem: "node", Role: RoleMCPServer}
	assignIdentities(root, []*Project{server})

	if server.OwnershipRoot != filepath.Clean(componentDir) {
		t.Errorf("expected ownership root to be promoted to the valid server.json's directory %q, got %q", componentDir, server.OwnershipRoot)
	}
}

// Discovery walks the tree in lexical order, so a server's dependencies can
// be discovered both before (a-lib) and after (z-lib) the server itself.
// Every dependency must get its real stable ID: transitiveClosure trusts
// LocalDepIDs whenever any of them resolves, so a single empty ID used to
// drop z-lib from the target's scope while a-lib kept it looking healthy.
func TestResolve_DependencyDiscoveredAfterItsDependentStaysInScope(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{
		"name": "server",
		"dependencies": {"@modelcontextprotocol/sdk": "^1", "a-lib": "workspace:*", "z-lib": "workspace:*"}
	}`)
	writeFile(t, filepath.Join(root, "index.js"), `const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js"); new McpServer();`)
	writeFile(t, filepath.Join(root, "a-lib", "package.json"), `{"name": "a-lib"}`)
	writeFile(t, filepath.Join(root, "z-lib", "package.json"), `{"name": "z-lib"}`)

	resolution, err := Resolve(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range resolution.Projects {
		for _, id := range p.LocalDepIDs {
			if id == "" {
				t.Errorf("project %s has an empty LocalDepIDs entry: %v", p.Name, p.LocalDepIDs)
			}
		}
	}
	if len(resolution.Targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(resolution.Targets))
	}
	included := map[string]bool{}
	for _, p := range resolution.Targets[0].Included {
		included[p.Name] = true
	}
	if !included["a-lib"] || !included["z-lib"] {
		t.Errorf("target scope = %v, want both a-lib and z-lib included", included)
	}
}
