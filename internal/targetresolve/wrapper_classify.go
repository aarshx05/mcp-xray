package targetresolve

import (
	"fmt"
	"path/filepath"
	"regexp"
)

// hasOwnEntrypointEvidence reports whether p has independent proof of being
// a launchable entrypoint in its own right, as opposed to being reachable
// merely as a downstream dependency of something else: a package.json
// "bin" entry (Node, cheap/no I/O -- checked first) or a source-level
// startup-call signal (wrapperEntrypointPatterns, signals.go) found in its
// own directory.
func hasOwnEntrypointEvidence(p *Project, allProjects []*Project) bool {
	if len(p.BinNames) > 0 {
		return true
	}
	pattern, ok := wrapperEntrypointPatterns[p.Ecosystem]
	if !ok {
		return false
	}
	exts, ok := ecosystemSourceExtensions[p.Ecosystem]
	if !ok {
		return false
	}
	signals := projectSourceSignals(p, allProjects, exts, map[string]*regexp.Regexp{"entrypoint": pattern})
	return signals["entrypoint"]
}

// promoteWrapperServers classifies a project RoleMCPServer when it has its
// own executability evidence (a bin entry or a startup call, see
// hasOwnEntrypointEvidence) AND the transitive closure of its
// workspace-local dependencies (graph.go's transitiveClosure) contains a
// project already classified RoleMCPServer -- i.e. the real SDK
// server-construction call lives in a dependency, not in this project's
// own source (a "wrapper" or "composed" server).
//
// For example, @twilio-alpha/mcp has a "bin" entry and a
// `.connect(transport)` call, but the `new Server(...)` call lives in the
// sibling @twilio-alpha/openapi-mcp-server it depends on.
//
// Test-shaped projects (isTestShapedProject) are never promoted: a test
// harness that reaches a real server is not a standalone target.
//
// Runs to a fixed point (bounded by len(projects) iterations) so a
// multi-hop wrapper chain (a wrapper of a wrapper) is fully resolved, not
// just one hop.
func promoteWrapperServers(projects []*Project) {
	byDir := make(map[string]*Project, len(projects))
	for _, p := range projects {
		byDir[filepath.Clean(p.Dir)] = p
	}

	for iterations := 0; iterations < len(projects); iterations++ {
		changed := false
		for _, p := range projects {
			if p.Role == RoleMCPServer {
				continue
			}
			if p.Ecosystem == "" || p.Ecosystem == "unknown" {
				continue
			}
			if isTestShapedProject(p) {
				continue
			}
			if !hasOwnEntrypointEvidence(p, projects) {
				continue
			}
			for _, dep := range transitiveClosure(p, byDir) {
				if dep != p && dep.Role == RoleMCPServer {
					p.Role = RoleMCPServer
					p.Evidence = append(p.Evidence, fmt.Sprintf(
						"classified as a wrapper/composed MCP server: has its own executability evidence (bin entry or startup call), and its workspace-local dependency closure reaches the confirmed MCP server %s",
						dep.Name,
					))
					changed = true
					break
				}
			}
		}
		if !changed {
			break
		}
	}
}
