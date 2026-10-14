package targetresolve

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	goSDKModulePath        = "github.com/modelcontextprotocol/go-sdk"
	nodeSDKPackage         = "@modelcontextprotocol/sdk"
	dotnetSDKPackagePrefix = "ModelContextProtocol"
	javaSDKGroupID         = "io.modelcontextprotocol.sdk"
	rustSDKCrateName       = "rmcp"
)

var (
	// Each server/client pattern matches either a construction call or an
	// import of the SDK's server (resp. client) namespace, so a server that
	// subclasses or wraps the SDK type is found as well as one that calls
	// its constructor. Patterns are qualified with the SDK's own identifiers
	// (mcp.NewServer, not a bare NewServer) and are only checked against
	// projects whose manifest declares the matching SDK, which keeps false
	// positives down. Import aliasing (`import s "github.com/.../mcp"`)
	// evades them: an accepted limit of a regex signal.
	//
	// Go is call-syntax-only: its SDK has no separate server and client
	// packages to import.
	goServerPattern = regexp.MustCompile(`mcp\.NewServer\(`)
	goClientPattern = regexp.MustCompile(`mcp\.NewClient\(`)

	// Node: a construction call, or any quoted import/require specifier
	// naming the SDK's server (resp. client) sub-path however the imported
	// symbol is then used -- `class RushMCPServer extends McpServer` never
	// calls `new McpServer(...)`.
	nodeServerPattern = regexp.MustCompile(`new\s+(McpServer|Server)\s*\(|["']@modelcontextprotocol/sdk/server(?:/[^"']*)?["']`)
	nodeClientPattern = regexp.MustCompile(`new\s+Client\s*\(|["']@modelcontextprotocol/sdk/client(?:/[^"']*)?["']`)

	// Python: the sub-signals are also used on their own by
	// classifyPythonScriptProject for manifest-less scripts.
	//
	// The namespace patterns match only the official mcp package's
	// mcp.server/mcp.client subpackages, never a bare `import fastmcp`: the
	// standalone fastmcp package exports both FastMCP (server) and Client
	// from its top level, so that import does not say which side it is.
	pythonServerNamespaceImportPattern = regexp.MustCompile(`\bfrom\s+mcp\.server(?:\.\w+)*\s+import\b|\bimport\s+mcp\.server(?:\.\w+)*\b`)
	pythonClientNamespaceImportPattern = regexp.MustCompile(`\bfrom\s+mcp\.client(?:\.\w+)*\s+import\b|\bimport\s+mcp\.client(?:\.\w+)*\b`)
	// pythonServerConstructionPattern matches a FastMCP(...) call or a class
	// subclassing FastMCP (class Foo(FastMCP): ...), which never calls it.
	pythonServerConstructionPattern = regexp.MustCompile(`FastMCP\s*\(|class\s+\w+\s*\([^)]*\bFastMCP\b[^)]*\)\s*:`)
	pythonClientConstructionPattern = regexp.MustCompile(`ClientSession\s*\(`)

	// The namespace clause also covers a server built on the low-level
	// mcp.server.lowlevel.Server API, which never calls FastMCP(...).
	pythonServerPattern = regexp.MustCompile(pythonServerNamespaceImportPattern.String() + `|` + pythonServerConstructionPattern.String())
	pythonClientPattern = regexp.MustCompile(pythonClientNamespaceImportPattern.String() + `|` + pythonClientConstructionPattern.String())

	// .NET: dotnetServerPattern requires a `.` immediately before
	// Add<anything>McpServer( so it matches a call site
	// (builder.Services.AddAzureMcpServer(...)) and not the definition of
	// such a helper, where the return type precedes the name. The wildcard
	// is there because servers commonly wrap the SDK's AddMcpServer() in a
	// helper of their own (AddAzureMcpServer), which is then the only call
	// a server's source makes.
	dotnetServerPattern = regexp.MustCompile(`\.Add\w*McpServer\s*\(|\busing\s+ModelContextProtocol\.Server(?:\.\w+)*\s*;`)
	dotnetClientPattern = regexp.MustCompile(`\.AddMcpClient\s*\(|McpClientFactory\.Create|\busing\s+ModelContextProtocol\.Client(?:\.\w+)*\s*;`)

	// Java: `import io.modelcontextprotocol.server...;` or the builder
	// entry point McpServer.sync|async(...), and the client equivalents.
	javaServerNamespaceImportPattern = regexp.MustCompile(`\bimport\s+io\.modelcontextprotocol\.server(?:\.\w+)*\s*;`)
	javaServerConstructionPattern    = regexp.MustCompile(`\bMcpServer\.(?:sync|async)\s*\(`)
	javaClientNamespaceImportPattern = regexp.MustCompile(`\bimport\s+io\.modelcontextprotocol\.client(?:\.\w+)*\s*;`)
	javaClientConstructionPattern    = regexp.MustCompile(`\bMcpClient\.(?:sync|async)\s*\(`)
	javaServerPattern                = regexp.MustCompile(javaServerNamespaceImportPattern.String() + `|` + javaServerConstructionPattern.String())
	javaClientPattern                = regexp.MustCompile(javaClientNamespaceImportPattern.String() + `|` + javaClientConstructionPattern.String())

	// Rust: rmcp servers implement the ServerHandler trait (clients,
	// ClientHandler). The alternatives cover a grouped use
	// (`use rmcp::{..., handler::server::ServerHandler};`), a flat qualified
	// path, and the impl block itself, bare or path-qualified
	// (`impl mcp::ServerHandler for`, when the crate is renamed in
	// Cargo.toml).
	rustServerPattern = regexp.MustCompile(`\brmcp::\{[^}]*\bServerHandler\b|\brmcp::(?:\w+::)*ServerHandler\b|\bimpl\s+(?:\w+::)*ServerHandler\s+for\b`)
	rustClientPattern = regexp.MustCompile(`\brmcp::\{[^}]*\bClientHandler\b|\brmcp::(?:\w+::)*ClientHandler\b|\bimpl\s+(?:\w+::)*ClientHandler\s+for\b`)
)

// Patterns used only to classify a manifest-less Python script
// (discover_python_script.go): pythonMainGuardPattern and
// pythonRunCallPattern require an executable entrypoint, not just an import,
// before such a script is classified a server.
var (
	pythonMainGuardPattern = regexp.MustCompile(`if\s+__name__\s*==\s*['"]__main__['"]\s*:`)
	pythonRunCallPattern   = regexp.MustCompile(`\.run\s*\(|\.serve\s*\(`)
	// legacyPythonScriptPrefilterPattern is the cheap check discovery runs
	// on every manifest-less .py file to pick candidates; classification
	// (classifyPythonScriptProject) then decides their Role.
	legacyPythonScriptPrefilterPattern = regexp.MustCompile(`\bfastmcp\b|\bmcp\.server\b|\bmcp\.client\b`)
)

// ecosystemSourceExtensions are the source files each ecosystem's
// classifier and hasOwnEntrypointEvidence read.
var ecosystemSourceExtensions = map[string][]string{
	"go":     {".go"},
	"node":   {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"},
	"python": {".py"},
	"dotnet": {".cs"},
	"java":   {".java"},
	"rust":   {".rs"},
}

// wrapperEntrypointPatterns are per-ecosystem "this file starts something
// up" signals: a constructed server being run, served or connected, as
// opposed to merely imported. hasOwnEntrypointEvidence uses them to
// recognize a thin wrapper entrypoint whose server construction lives in a
// workspace-local dependency. Java and Rust use the language's own
// entrypoint marker (static void main, fn main) because their SDKs have no
// single startup call to look for.
var wrapperEntrypointPatterns = map[string]*regexp.Regexp{
	"go":     regexp.MustCompile(`\.Run\s*\(`),
	"node":   regexp.MustCompile(`\.connect\s*\(|\.listen\s*\(`),
	"python": regexp.MustCompile(`\.run\s*\(|\.serve\s*\(`),
	"dotnet": regexp.MustCompile(`\.Run\s*\(\)|\.RunAsync\s*\(`),
	"java":   regexp.MustCompile(`\bpublic\s+static\s+void\s+main\s*\(`),
	"rust":   regexp.MustCompile(`\bfn\s+main\s*\(`),
}

// classifyRoles assigns an initial Role to every project, independently of
// the dependency graph (shared-library promotion happens afterward, in
// graph.go, once it's known which projects are actually referenced by a
// server). Each project gets exactly one of: RoleMCPServer, RoleMCPClient,
// RoleConsumerConfigOnly, or RoleUnrelated.
func classifyRoles(projects []*Project) {
	for _, p := range projects {
		role, evidence := classifyProject(p, projects)
		p.Role = role
		p.Evidence = evidence
	}
}

func classifyProject(p *Project, allProjects []*Project) (Role, []string) {
	if isTestShapedProject(p) {
		return classifyTestShapedProject(p, allProjects)
	}
	return classifyByEcosystem(p, allProjects)
}

// classifyByEcosystem classifies p from its ecosystem's SDK profile: a
// project whose manifest declares the MCP SDK is a server or a client by
// what its source constructs; one without it can only be a consumer config
// or unrelated.
func classifyByEcosystem(p *Project, allProjects []*Project) (Role, []string) {
	if p.Ecosystem == "python-script" {
		return classifyPythonScriptProject(p)
	}
	profile, ok := sdkProfiles[p.Ecosystem]
	if !ok {
		return RoleUnrelated, nil
	}
	sdk, hasSDK, err := profile.sdkDependency(p)
	if err != nil {
		return RoleUnrelated, nil
	}
	if !hasSDK {
		return consumerOrUnrelated(p)
	}
	signals := projectSourceSignals(p, allProjects, ecosystemSourceExtensions[p.Ecosystem], map[string]*regexp.Regexp{
		"server": profile.server,
		"client": profile.client,
	})
	return roleFromSignals(sdk, signals)
}

// sdkProfile is how one ecosystem's MCP SDK shows up: the dependency a
// project's manifest declares, and the source patterns of server and client
// code.
type sdkProfile struct {
	// sdkDependency names the MCP SDK p's manifest depends on; ok is false
	// when it depends on none, and err is set when the manifest is
	// unreadable.
	sdkDependency  func(p *Project) (sdk string, ok bool, err error)
	server, client *regexp.Regexp
}

var sdkProfiles = map[string]sdkProfile{
	"go":     {goSDKDependency, goServerPattern, goClientPattern},
	"node":   {nodeSDKDependency, nodeServerPattern, nodeClientPattern},
	"python": {pythonProjectSDKDependency, pythonServerPattern, pythonClientPattern},
	"dotnet": {dotnetSDKDependency, dotnetServerPattern, dotnetClientPattern},
	"java":   {javaSDKDependency, javaServerPattern, javaClientPattern},
	"rust":   {rustSDKDependency, rustServerPattern, rustClientPattern},
}

// testShapedPathSegmentPattern and testShapedNameSuffixPattern together
// decide whether a project is "test-shaped": its directory sits under a
// test/tests/__tests__ path segment, or its own directory basename ends in
// a conventional test suffix (.Tests/.Test/_test/_tests, case-insensitive).
// A test project that constructs a real server for its integration tests
// (Microsoft.ModelContextProtocol.HttpServer.Distributed.Tests) is
// indistinguishable from a server by source signal alone.
var (
	testShapedPathSegmentPattern = regexp.MustCompile(`(?i)(^|[/\\])(tests?|__tests__)([/\\]|$)`)
	testShapedNameSuffixPattern  = regexp.MustCompile(`(?i)([._]tests?)$`)
)

// isTestShapedProject reports whether p's directory looks like a test
// project by naming convention alone, independent of its source content. A
// test-shaped project is never classified RoleMCPServer regardless of what
// SDK construction calls its own source contains (see classifyProject and
// promoteWrapperServers in wrapper_classify.go, which both consult this).
//
// Only the repository-relative location (p.RelDir) is matched: a checkout
// that happens to live under an ancestor named test/tests/__tests__ must not
// make every project inside it look test-shaped (demoting every server and
// leaving nothing selectable). The repository root itself is never
// test-shaped by name -- its directory name is chosen by whoever cloned it,
// not by the project. Without a known RelDir, only the project's own
// directory basename is checked, the one part of an absolute path that is
// always the project's own.
func isTestShapedProject(p *Project) bool {
	switch p.RelDir {
	case "":
		return testShapedNameSuffixPattern.MatchString(filepath.Base(p.Dir))
	case ".":
		return false
	}
	return testShapedPathSegmentPattern.MatchString(p.RelDir) || testShapedNameSuffixPattern.MatchString(path.Base(p.RelDir))
}

// classifyTestShapedProject still runs the normal ecosystem classification
// (to get the right Evidence trail and to distinguish a genuine
// RoleMCPClient/RoleConsumerConfigOnly from RoleUnrelated where relevant),
// but downgrades a RoleMCPServer conclusion to RoleMCPClient -- a test
// project that constructs a server to exercise it is, at most, acting as
// that server's own client/harness, never a standalone target of its own.
func classifyTestShapedProject(p *Project, allProjects []*Project) (Role, []string) {
	role, evidence := classifyByEcosystem(p, allProjects)
	if role != RoleMCPServer {
		return role, evidence
	}
	return RoleMCPClient, append(evidence, "directory is test-shaped (path segment or name suffix); a server-construction call here is treated as test harness code, not a standalone server")
}

func goSDKDependency(p *Project) (string, bool, error) {
	mf, err := readGoMod(p.ManifestPath)
	if err != nil {
		return "", false, err
	}
	for _, req := range mf.Require {
		if req.Mod.Path == goSDKModulePath || strings.HasPrefix(req.Mod.Path, goSDKModulePath+"/") {
			return goSDKModulePath, true, nil
		}
	}
	return "", false, nil
}

func nodeSDKDependency(p *Project) (string, bool, error) {
	pkg, err := readPackageJSON(p.ManifestPath)
	if err != nil {
		return "", false, err
	}
	_, ok := pkg.allDependencies()[nodeSDKPackage]
	return nodeSDKPackage, ok, nil
}

func pythonProjectSDKDependency(p *Project) (string, bool, error) {
	doc, err := readPyprojectToml(p.ManifestPath)
	if err != nil {
		return "", false, err
	}
	sdk, ok := pythonSDKDependency(doc)
	return sdk, ok, nil
}

func dotnetSDKDependency(p *Project) (string, bool, error) {
	doc, err := readCsproj(p.ManifestPath)
	if err != nil {
		return "", false, err
	}
	return dotnetSDKPackagePrefix, dotnetPackageReferencePrefix(doc, dotnetSDKPackagePrefix), nil
}

func javaSDKDependency(p *Project) (string, bool, error) {
	doc, err := readPom(p.ManifestPath)
	if err != nil {
		return "", false, err
	}
	return javaSDKGroupID, javaGroupIDDependency(doc, javaSDKGroupID), nil
}

// rustSDKDependency also follows dependencies the crate inherits from its
// Cargo workspace.
func rustSDKDependency(p *Project) (string, bool, error) {
	doc, err := readCargoToml(p.ManifestPath)
	if err != nil {
		return "", false, err
	}
	var workspace *cargoWorkspace
	if repoRoot, ok := projectRepoRoot(p); ok {
		workspace = findCargoWorkspace(repoRoot, p.Dir, doc, make(map[string]*cargoWorkspace))
	}
	return rustSDKCrateName, cargoHasDependency(doc, rustSDKCrateName, workspace), nil
}

// roleFromSignals turns the construction calls found in source into a Role
// for a project that depends on an MCP SDK. A server signal wins over a
// client one (a server may use a client internally; it still has to be
// scanned as a server). With neither signal the project defaults to client:
// an unrecognized SDK use is left out of the target list rather than made a
// selectable target.
func roleFromSignals(sdkEvidence string, signals map[string]bool) (Role, []string) {
	evidence := []string{"depends on " + sdkEvidence}
	switch {
	case signals["server"]:
		return RoleMCPServer, append(evidence, "source contains a server-construction call")
	case signals["client"]:
		return RoleMCPClient, append(evidence, "source contains a client-construction call")
	default:
		return RoleMCPClient, append(evidence, "no server/client construction call found; defaulting to client")
	}
}

// consumerOrUnrelated handles a project with no MCP SDK dependency of its
// own: it is classified RoleConsumerConfigOnly if it merely configures
// external MCP servers (an mcp.json-shaped file with an "mcpServers" key),
// and RoleUnrelated otherwise: a client configuration file never makes a
// project a server.
func consumerOrUnrelated(p *Project) (Role, []string) {
	if hasConsumerConfig(p) {
		return RoleConsumerConfigOnly, []string{"contains an MCP client configuration file but no MCP SDK dependency"}
	}
	return RoleUnrelated, nil
}

// hasConsumerConfig looks for an MCP client configuration file (mcp.json,
// .cursor/mcp.json, a claude_desktop_config.json-shaped file, ...) under the
// project's directory, confirming it by parsing the file and checking for
// the "mcpServers" key rather than matching on filename alone.
func hasConsumerConfig(p *Project) bool {
	found := false
	_ = walkFiles(p.Dir, nil, func(path string, info os.FileInfo) error {
		name := strings.ToLower(info.Name())
		if name != "mcp.json" && name != "mcp_config.json" && !strings.Contains(name, "claude_desktop_config") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var doc map[string]interface{}
		if json.Unmarshal(data, &doc) != nil {
			return nil
		}
		if _, ok := doc["mcpServers"]; ok {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// pythonSDKDependency reports whether the pyproject.toml document depends on
// the official "mcp" package or "fastmcp", checking both Poetry-style
// dependency tables (exact key match) and PEP 621's [project].dependencies
// array of PEP 508 specifier strings.
func pythonSDKDependency(doc map[string]interface{}) (string, bool) {
	sdkNames := map[string]bool{"mcp": true, "fastmcp": true}

	for _, deps := range poetryDependencyTables(doc) {
		for name := range deps {
			if sdkNames[strings.ToLower(name)] {
				return name, true
			}
		}
	}

	if depsVal, ok := valueAt(doc, "project", "dependencies"); ok {
		if arr, ok := depsVal.([]interface{}); ok {
			for _, item := range arr {
				spec, ok := item.(string)
				if !ok {
					continue
				}
				name := pep508PackageName(spec)
				if sdkNames[strings.ToLower(name)] {
					return name, true
				}
			}
		}
	}

	return "", false
}

// pep508PackageName extracts the package name from a PEP 508 dependency
// specifier string, e.g. "fastmcp>=2.0" -> "fastmcp", "mcp[cli]==1.2" -> "mcp".
func pep508PackageName(spec string) string {
	spec = strings.TrimSpace(spec)
	for i, r := range spec {
		switch r {
		case '[', '=', '>', '<', '!', '~', ';', ' ':
			return spec[:i]
		}
	}
	return spec
}

// projectSourceSignals reports which of the named patterns match a file
// under project.Dir whose name ends with one of extensions. It never
// descends into another project nested in that tree, so a nested project's
// code cannot change this project's role.
func projectSourceSignals(project *Project, allProjects []*Project, extensions []string, patterns map[string]*regexp.Regexp) map[string]bool {
	projDir := filepath.Clean(project.Dir)
	nestedProjectDirs := make(map[string]bool)
	for _, other := range allProjects {
		if otherDir := filepath.Clean(other.Dir); otherDir != projDir && within(otherDir, projDir) {
			nestedProjectDirs[otherDir] = true
		}
	}
	isNestedProject := func(dir string) bool { return nestedProjectDirs[filepath.Clean(dir)] }

	found := make(map[string]bool, len(patterns))
	_ = walkFiles(project.Dir, isNestedProject, func(path string, info os.FileInfo) error {
		if !hasAnyExt(info.Name(), extensions) {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for name, pattern := range patterns {
			if !found[name] && pattern.Match(content) {
				found[name] = true
			}
		}
		if len(found) == len(patterns) {
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func hasAnyExt(name string, exts []string) bool {
	for _, ext := range exts {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}
