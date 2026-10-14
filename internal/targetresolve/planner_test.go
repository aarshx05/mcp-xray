package targetresolve

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestBuildScanPlanSharedUnitAndResidualScope(t *testing.T) {
	root := t.TempDir()
	shared := filepath.Join(root, "shared")
	a := filepath.Join(root, "a")
	b := filepath.Join(root, "b")
	for _, dir := range []string{shared, a, b} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	projects := []*Project{
		{ID: "pa", Name: "a", Dir: a, OwnershipRoot: a, ComponentID: "ca"},
		{ID: "pb", Name: "b", Dir: b, OwnershipRoot: b, ComponentID: "cb"},
		{ID: "ps", Name: "shared", Dir: shared, OwnershipRoot: shared, ComponentID: "cs"},
	}
	targets := []*Target{
		{ID: "ta", Name: "a", Project: projects[0], Included: []*Project{projects[0], projects[2]}, IncludedReasons: map[string]InclusionReason{a: InclusionPrimary, shared: InclusionSharedDependency}},
		{ID: "tb", Name: "b", Project: projects[1], Included: []*Project{projects[1], projects[2]}, IncludedReasons: map[string]InclusionReason{b: InclusionPrimary, shared: InclusionSharedDependency}},
	}
	resolution := &Resolution{RepoRoot: root, Targets: targets, Inventory: nil}
	plan, err := BuildScanPlan(resolution, PlanOptions{AllTargets: true, IncludeRepoGlobal: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.SelectedTargets) != 2 {
		t.Fatalf("selected targets = %d, want 2", len(plan.SelectedTargets))
	}
	if len(plan.Units) != 4 {
		t.Fatalf("scan units = %d, want 4 (a, b, shared, global)", len(plan.Units))
	}
	sharedCount := 0
	for _, unit := range plan.Units {
		if unit.Root == shared {
			sharedCount++
			if len(unit.TargetIDs) != 2 {
				t.Errorf("shared unit target attribution = %v, want both targets", unit.TargetIDs)
			}
		}
	}
	if sharedCount != 1 {
		t.Fatalf("shared unit count = %d, want 1", sharedCount)
	}
	globalFound := false
	for _, unit := range plan.Units {
		if unit.Root == root {
			globalFound = true
			if len(unit.ExcludedDirs) != 3 {
				t.Errorf("global exclusions = %v, want scheduled roots", unit.ExcludedDirs)
			}
		}
	}
	if !globalFound {
		t.Error("expected one repository-global unit")
	}
}

// TestBuildScanPlan_ExcludesNestedForeignProject reproduces the reported
// flaw directly: selecting a target rooted at appDir must not also scan an
// unrelated project that happens to live in a subdirectory of appDir.
func TestBuildScanPlan_ExcludesNestedForeignProject(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	foreignDir := filepath.Join(root, "app", "tools", "other")
	for _, dir := range []string{appDir, foreignDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	appProject := &Project{ID: "p-app", Name: "app", Dir: appDir, OwnershipRoot: appDir, ComponentID: "c-app"}
	foreignProject := &Project{ID: "p-foreign", Name: "other", Dir: foreignDir, OwnershipRoot: foreignDir, ComponentID: "c-foreign", Role: RoleUnrelated}
	target := &Target{ID: "t-app", Name: "app", Project: appProject, Included: []*Project{appProject}, IncludedReasons: map[string]InclusionReason{appDir: InclusionPrimary}}

	resolution := &Resolution{RepoRoot: root, Projects: []*Project{appProject, foreignProject}, Targets: []*Target{target}}
	plan, err := BuildScanPlan(resolution, PlanOptions{TargetIDs: []string{"t-app"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Units) != 1 {
		t.Fatalf("scan units = %d, want 1", len(plan.Units))
	}
	unit := plan.Units[0]
	want := filepath.ToSlash(filepath.Join("tools", "other"))
	found := false
	for _, excluded := range unit.ExcludedDirs {
		if excluded == want {
			found = true
		}
	}
	if !found {
		t.Errorf("expected unit.ExcludedDirs to contain %q, got %v", want, unit.ExcludedDirs)
	}
}

// TestBuildScanPlan_DoesNotExcludeLegitimateNestedSharedComponent is the
// regression check for the case nestedForeignExcludes must NOT touch: a
// shared component nested inside the primary project's own directory tree,
// genuinely included in the same target, must remain scanned. dropNestedRoots
// folds the shared component's own unit into the primary's here (same as
// TestBuildScanPlanSharedUnitAndResidualScope's top-level "shared" case, just
// nested instead of a sibling), so this also proves nestedForeignExcludes
// correctly recognizes an included project even after its own separate unit
// was dropped.
func TestBuildScanPlan_DoesNotExcludeLegitimateNestedSharedComponent(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	sharedDir := filepath.Join(root, "app", "vendor", "shared-lib")
	for _, dir := range []string{appDir, sharedDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	appProject := &Project{ID: "p-app", Name: "app", Dir: appDir, OwnershipRoot: appDir, ComponentID: "c-app"}
	sharedProject := &Project{ID: "p-shared", Name: "shared-lib", Dir: sharedDir, OwnershipRoot: sharedDir, ComponentID: "c-shared"}
	target := &Target{ID: "t-app", Name: "app", Project: appProject, Included: []*Project{appProject, sharedProject}, IncludedReasons: map[string]InclusionReason{appDir: InclusionPrimary, sharedDir: InclusionSharedDependency}}

	resolution := &Resolution{RepoRoot: root, Projects: []*Project{appProject, sharedProject}, Targets: []*Target{target}}
	plan, err := BuildScanPlan(resolution, PlanOptions{TargetIDs: []string{"t-app"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Units) != 1 {
		t.Fatalf("scan units = %d, want 1 (dropNestedRoots should fold the nested shared component into the app unit)", len(plan.Units))
	}
	unwanted := filepath.ToSlash(filepath.Join("vendor", "shared-lib"))
	for _, excluded := range plan.Units[0].ExcludedDirs {
		if excluded == unwanted {
			t.Errorf("legitimately included shared component %q must not be excluded, got ExcludedDirs=%v", unwanted, plan.Units[0].ExcludedDirs)
		}
	}
}

// TestBuildScanPlan_NestedForeignExcludeDoesNotAffectRepoGlobalUnit confirms
// the repository-global unit keeps its own, deliberately different exclusion
// rule (residualExcludes: only the scheduled roots) rather than
// also applying nestedForeignExcludes -- a repo-global scan is documented to
// intentionally still cover other discovered-but-unselected projects.
func TestBuildScanPlan_NestedForeignExcludeDoesNotAffectRepoGlobalUnit(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	foreignDir := filepath.Join(root, "app", "tools", "other")
	for _, dir := range []string{appDir, foreignDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	appProject := &Project{ID: "p-app", Name: "app", Dir: appDir, OwnershipRoot: appDir, ComponentID: "c-app"}
	foreignProject := &Project{ID: "p-foreign", Name: "other", Dir: foreignDir, OwnershipRoot: foreignDir, ComponentID: "c-foreign", Role: RoleUnrelated}
	target := &Target{ID: "t-app", Name: "app", Project: appProject, Included: []*Project{appProject}, IncludedReasons: map[string]InclusionReason{appDir: InclusionPrimary}}

	resolution := &Resolution{RepoRoot: root, Projects: []*Project{appProject, foreignProject}, Targets: []*Target{target}}
	plan, err := BuildScanPlan(resolution, PlanOptions{TargetIDs: []string{"t-app"}, IncludeRepoGlobal: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Units) != 2 {
		t.Fatalf("scan units = %d, want 2 (app, global)", len(plan.Units))
	}
	for _, unit := range plan.Units {
		if unit.Root != root {
			continue
		}
		// The global unit excludes the one scheduled root ("app") and
		// nothing else -- in particular NOT "app/tools/other", which is
		// nested inside an excluded directory already and, per the
		// repo-global unit's own documented semantics, is not the kind of
		// exclusion this unit applies at all.
		if len(unit.ExcludedDirs) != 1 || unit.ExcludedDirs[0] != "app" {
			t.Errorf("expected the global unit to exclude only [\"app\"], got %v", unit.ExcludedDirs)
		}
	}
}

// TestWorkspaceRootFallback_TriggersWhenUnitHasNoOwnLockfile reproduces the
// real npm/yarn/pnpm workspace shape found in twilio-labs/mcp during
// benchmarking: two separate targets, each with its own package.json but no
// lockfile of its own -- only the workspace root's package-lock.json pins
// exact dependency versions. Both units should fall back to it, and the
// resulting finding ownership should credit both targets, not neither.
func TestWorkspaceRootFallback_TriggersWhenUnitHasNoOwnLockfile(t *testing.T) {
	root := t.TempDir()
	mcpDir := filepath.Join(root, "packages", "mcp")
	otherDir := filepath.Join(root, "packages", "openapi-mcp-server")
	for _, dir := range []string{mcpDir, otherDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mcpProject := &Project{ID: "p-mcp", Name: "mcp", Dir: mcpDir, OwnershipRoot: mcpDir, ComponentID: "c-mcp", Ecosystem: "node"}
	otherProject := &Project{ID: "p-other", Name: "openapi-mcp-server", Dir: otherDir, OwnershipRoot: otherDir, ComponentID: "c-other", Ecosystem: "node"}
	mcpTarget := &Target{ID: "t-mcp", Name: "mcp", Project: mcpProject, Included: []*Project{mcpProject}, IncludedReasons: map[string]InclusionReason{mcpDir: InclusionPrimary}, ComponentID: "c-mcp"}
	otherTarget := &Target{ID: "t-other", Name: "openapi-mcp-server", Project: otherProject, Included: []*Project{otherProject}, IncludedReasons: map[string]InclusionReason{otherDir: InclusionPrimary}, ComponentID: "c-other"}

	resolution := &Resolution{
		RepoRoot: root,
		Projects: []*Project{mcpProject, otherProject},
		Targets:  []*Target{mcpTarget, otherTarget},
		Inventory: []InventoryEntry{
			{Path: "package-lock.json", Lockfile: true},
		},
	}
	plan, err := BuildScanPlan(resolution, PlanOptions{AllTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Units) != 2 {
		t.Fatalf("scan units = %d, want 2", len(plan.Units))
	}
	for _, unit := range plan.Units {
		if fallbackNames(unit) != "package-lock.json" {
			t.Errorf("unit %s: FallbackLockfiles = %v, want [\"package-lock.json\"]", unit.RelativeRoot, unit.FallbackLockfiles)
		}
	}
	fo := plan.FileOwnership["package-lock.json"]
	if fo == nil {
		t.Fatal("expected plan.FileOwnership[\"package-lock.json\"] to be set")
	}
	if fo.Relation != RelationWorkspaceRoot {
		t.Errorf("Relation = %q, want %q", fo.Relation, RelationWorkspaceRoot)
	}
	if len(fo.TargetIDs) != 2 || fo.TargetIDs[0] != "t-mcp" || fo.TargetIDs[1] != "t-other" {
		t.Errorf("TargetIDs = %v, want both t-mcp and t-other", fo.TargetIDs)
	}
}

// TestWorkspaceRootFallback_NoTriggerWhenUnitHasOwnLockfile is the negative
// regression matching aws-mcp's shape in the same benchmarking session: each
// target manages its own dependencies independently (its own uv.lock), so a
// root-level lockfile must never be treated as a fallback source even when
// one happens to exist.
func TestWorkspaceRootFallback_NoTriggerWhenUnitHasOwnLockfile(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "server")
	if err := os.MkdirAll(serverDir, 0o755); err != nil {
		t.Fatal(err)
	}
	project := &Project{ID: "p-server", Name: "server", Dir: serverDir, OwnershipRoot: serverDir, ComponentID: "c-server", Ecosystem: "python"}
	target := &Target{ID: "t-server", Name: "server", Project: project, Included: []*Project{project}, IncludedReasons: map[string]InclusionReason{serverDir: InclusionPrimary}}

	resolution := &Resolution{
		RepoRoot: root,
		Projects: []*Project{project},
		Targets:  []*Target{target},
		Inventory: []InventoryEntry{
			{Path: filepath.ToSlash(filepath.Join("server", "uv.lock")), Lockfile: true},
			{Path: "requirements.txt", Lockfile: true}, // an unrelated root-level lockfile
		},
	}
	plan, err := BuildScanPlan(resolution, PlanOptions{AllTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Units) != 1 {
		t.Fatalf("scan units = %d, want 1", len(plan.Units))
	}
	if fallbackNames(plan.Units[0]) != "" {
		t.Errorf("expected no fallback when the unit already has its own lockfile, got %v", plan.Units[0].FallbackLockfiles)
	}
}

// TestWorkspaceRootFallback_EcosystemMismatchNeverFallsBack proves a
// Python target with no lockfile of its own is never backed by an unrelated
// Node lockfile that happens to sit at the repository root.
func TestWorkspaceRootFallback_EcosystemMismatchNeverFallsBack(t *testing.T) {
	root := t.TempDir()
	pyDir := filepath.Join(root, "pyserver")
	if err := os.MkdirAll(pyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	project := &Project{ID: "p-py", Name: "pyserver", Dir: pyDir, OwnershipRoot: pyDir, ComponentID: "c-py", Ecosystem: "python"}
	target := &Target{ID: "t-py", Name: "pyserver", Project: project, Included: []*Project{project}, IncludedReasons: map[string]InclusionReason{pyDir: InclusionPrimary}}

	resolution := &Resolution{
		RepoRoot:  root,
		Projects:  []*Project{project},
		Targets:   []*Target{target},
		Inventory: []InventoryEntry{{Path: "package-lock.json", Lockfile: true}},
	}
	plan, err := BuildScanPlan(resolution, PlanOptions{AllTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	if fallbackNames(plan.Units[0]) != "" {
		t.Errorf("expected no fallback across mismatched ecosystems, got %v", plan.Units[0].FallbackLockfiles)
	}
}

// TestWorkspaceRootFallback_ExcludedOwnLockfileStillTriggersFallback proves
// unitLockfileEcosystems respects the unit's own finalized exclusions: a
// lockfile that only exists inside a foreign nested project (already pruned
// by nestedForeignExcludes) must not count as "the unit has its own
// lockfile" -- that file will never actually reach the scanner.
func TestWorkspaceRootFallback_ExcludedOwnLockfileStillTriggersFallback(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	foreignDir := filepath.Join(root, "app", "vendor", "foreign")
	for _, dir := range []string{appDir, foreignDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	appProject := &Project{ID: "p-app", Name: "app", Dir: appDir, OwnershipRoot: appDir, ComponentID: "c-app", Ecosystem: "node"}
	foreignProject := &Project{ID: "p-foreign", Name: "foreign", Dir: foreignDir, OwnershipRoot: foreignDir, ComponentID: "c-foreign", Ecosystem: "node", Role: RoleUnrelated}
	target := &Target{ID: "t-app", Name: "app", Project: appProject, Included: []*Project{appProject}, IncludedReasons: map[string]InclusionReason{appDir: InclusionPrimary}}

	resolution := &Resolution{
		RepoRoot: root,
		Projects: []*Project{appProject, foreignProject},
		Targets:  []*Target{target},
		Inventory: []InventoryEntry{
			{Path: filepath.ToSlash(filepath.Join("app", "vendor", "foreign", "package-lock.json")), Lockfile: true},
			{Path: "package-lock.json", Lockfile: true},
		},
	}
	plan, err := BuildScanPlan(resolution, PlanOptions{TargetIDs: []string{"t-app"}})
	if err != nil {
		t.Fatal(err)
	}
	unit := plan.Units[0]
	excludesForeign := false
	for _, excluded := range unit.ExcludedDirs {
		if excluded == filepath.ToSlash(filepath.Join("vendor", "foreign")) {
			excludesForeign = true
		}
	}
	if !excludesForeign {
		t.Fatalf("expected the foreign nested project to be excluded, got ExcludedDirs=%v", unit.ExcludedDirs)
	}
	if fallbackNames(unit) != "package-lock.json" {
		t.Errorf("expected the excluded nested lockfile to NOT count as the unit's own, so it should fall back to the root; got FallbackLockfiles=%v", unit.FallbackLockfiles)
	}
}

// TestWorkspaceRootFallback_EvaluatesEachEcosystemIndependently covers a
// unit that represents two ecosystems at once (a Node package and a Python
// package sharing one directory). Its own uv.lock pins the Python side only;
// it must not suppress the Node side's fallback to the workspace-root
// package-lock.json, and the root uv.lock -- which the unit does not need --
// must not be attributed to the target.
func TestWorkspaceRootFallback_EvaluatesEachEcosystemIndependently(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	nodeProject := &Project{ID: "p-node", Name: "app", Dir: appDir, OwnershipRoot: appDir, ComponentID: "c-app", Ecosystem: "node"}
	pyProject := &Project{ID: "p-py", Name: "app-py", Dir: appDir, OwnershipRoot: appDir, ComponentID: "c-app", Ecosystem: "python"}
	target := &Target{ID: "t-app", Name: "app", Project: nodeProject, Included: []*Project{nodeProject, pyProject}, IncludedReasons: map[string]InclusionReason{appDir: InclusionPrimary}, ComponentID: "c-app"}

	resolution := &Resolution{
		RepoRoot: root,
		Projects: []*Project{nodeProject, pyProject},
		Targets:  []*Target{target},
		Inventory: []InventoryEntry{
			{Path: "app/uv.lock", Lockfile: true},
			{Path: "package-lock.json", Lockfile: true},
			{Path: "uv.lock", Lockfile: true},
		},
	}
	plan, err := BuildScanPlan(resolution, PlanOptions{AllTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Units) != 1 {
		t.Fatalf("scan units = %d, want 1", len(plan.Units))
	}
	if got := fallbackNames(plan.Units[0]); got != "package-lock.json" {
		t.Fatalf("FallbackLockfiles = %v, want [package-lock.json] (node has no own lockfile; python does)", got)
	}
	if fo := plan.FileOwnership["package-lock.json"]; fo == nil || len(fo.TargetIDs) != 1 || fo.TargetIDs[0] != "t-app" {
		t.Errorf("package-lock.json ownership = %+v, want attributed to t-app", fo)
	}
	if fo := plan.FileOwnership["uv.lock"]; fo != nil && len(fo.TargetIDs) != 0 {
		t.Errorf("root uv.lock ownership = %+v, want no target (the unit pins python itself)", fo)
	}
}

// TestWorkspaceRootFallback_CountsFoldedNestedProjects covers a unit whose
// scope also contains an included project nested under its root (its own
// unit folded into this one by dropNestedRoots). The nested Python package
// has no lockfile of its own, so the workspace-root uv.lock must back it even
// though the unit's primary Node package is fully pinned.
func TestWorkspaceRootFallback_CountsFoldedNestedProjects(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	helperDir := filepath.Join(appDir, "helper")
	if err := os.MkdirAll(helperDir, 0o755); err != nil {
		t.Fatal(err)
	}
	app := &Project{ID: "p-app", Name: "app", Dir: appDir, OwnershipRoot: appDir, ComponentID: "c-app", Ecosystem: "node"}
	helper := &Project{ID: "p-helper", Name: "helper", Dir: helperDir, OwnershipRoot: helperDir, ComponentID: "c-helper", Ecosystem: "python"}
	target := &Target{ID: "t-app", Name: "app", Project: app, Included: []*Project{app, helper}, IncludedReasons: map[string]InclusionReason{appDir: InclusionPrimary, helperDir: InclusionSharedDependency}, ComponentID: "c-app"}

	resolution := &Resolution{
		RepoRoot: root,
		Projects: []*Project{app, helper},
		Targets:  []*Target{target},
		Inventory: []InventoryEntry{
			{Path: "app/package-lock.json", Lockfile: true},
			{Path: "uv.lock", Lockfile: true},
		},
	}
	plan, err := BuildScanPlan(resolution, PlanOptions{AllTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Units) != 1 {
		t.Fatalf("scan units = %d, want 1 (helper folds into app)", len(plan.Units))
	}
	if got := fallbackNames(plan.Units[0]); got != "uv.lock" {
		t.Errorf("FallbackLockfiles = %v, want [uv.lock] for the folded python helper", got)
	}
}

// TestWorkspaceRootFallback_OnlyForSharedWorkspaceLockfileEcosystems: a
// nested Go module never shares the root module's go.sum (osv-scanner reads
// each module's own go.mod), so a Go unit without a go.sum must not trigger a
// workspace-root fallback. A manifest-less Python script, by contrast, has no
// package manager of its own and is backed by the root requirements.txt.
func TestWorkspaceRootFallback_OnlyForSharedWorkspaceLockfileEcosystems(t *testing.T) {
	root := t.TempDir()
	goDir := filepath.Join(root, "gosrv")
	scriptDir := filepath.Join(root, "script")
	for _, dir := range []string{goDir, scriptDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	goProject := &Project{ID: "p-go", Name: "gosrv", Dir: goDir, OwnershipRoot: goDir, ComponentID: "c-go", Ecosystem: "go"}
	scriptProject := &Project{ID: "p-script", Name: "script", Dir: scriptDir, OwnershipRoot: scriptDir, ComponentID: "c-script", Ecosystem: "python-script"}
	goTarget := &Target{ID: "t-go", Name: "gosrv", Project: goProject, Included: []*Project{goProject}, IncludedReasons: map[string]InclusionReason{goDir: InclusionPrimary}}
	scriptTarget := &Target{ID: "t-script", Name: "script", Project: scriptProject, Included: []*Project{scriptProject}, IncludedReasons: map[string]InclusionReason{scriptDir: InclusionPrimary}}

	resolution := &Resolution{
		RepoRoot: root,
		Projects: []*Project{goProject, scriptProject},
		Targets:  []*Target{goTarget, scriptTarget},
		Inventory: []InventoryEntry{
			{Path: "go.sum", Lockfile: true},
			{Path: "requirements.txt", Lockfile: true},
		},
	}
	plan, err := BuildScanPlan(resolution, PlanOptions{AllTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Units) != 2 {
		t.Fatalf("scan units = %d, want 2", len(plan.Units))
	}
	for _, unit := range plan.Units {
		switch unit.RelativeRoot {
		case "gosrv":
			if fallbackNames(unit) != "" {
				t.Errorf("go unit FallbackLockfiles = %v, want none", unit.FallbackLockfiles)
			}
		case "script":
			if fallbackNames(unit) != "requirements.txt" {
				t.Errorf("python-script unit FallbackLockfiles = %v, want [requirements.txt]", unit.FallbackLockfiles)
			}
		default:
			t.Errorf("unexpected unit %q", unit.RelativeRoot)
		}
	}
}

// A Python client script that merely sits in a Node server's folder is not
// part of the server's target, so it must not pull the repository's Python
// lockfile into that server's fallback (end to end through Resolve).
func TestWorkspaceRootFallback_IgnoresProjectsNoTargetIncludes(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"name": "monorepo", "private": true, "workspaces": ["servers/*"]}`)
	writeFile(t, filepath.Join(root, "package-lock.json"), `{}`)
	writeFile(t, filepath.Join(root, "requirements.txt"), "requests==2.19.0\n")
	writeFile(t, filepath.Join(root, "servers", "node", "package.json"), `{"name": "node-server", "dependencies": {"@modelcontextprotocol/sdk": "^1"}}`)
	writeFile(t, filepath.Join(root, "servers", "node", "index.js"), `const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js"); new McpServer();`)
	writeFile(t, filepath.Join(root, "servers", "node", "smoke_client.py"), "from mcp.client.stdio import stdio_client\n")

	resolution, err := Resolve(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolution.Targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(resolution.Targets))
	}
	plan, err := BuildScanPlan(resolution, PlanOptions{AllTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Units) != 1 {
		t.Fatalf("scan units = %d, want 1", len(plan.Units))
	}
	if got := fallbackNames(plan.Units[0]); got != "package-lock.json" {
		t.Errorf("FallbackLockfiles = %v, want [package-lock.json] only", got)
	}
}

// Several targets can share one unit without sharing its ecosystems. A root
// lockfile must be credited only to the targets whose own included projects
// need it, and that must not depend on which other targets are selected.
func TestWorkspaceRootFallback_AttributesOnlyToTargetsThatNeedIt(t *testing.T) {
	root := t.TempDir()
	aDir, bDir := filepath.Join(root, "a"), filepath.Join(root, "b")
	libsDir := filepath.Join(root, "libs")
	helperDir := filepath.Join(libsDir, "pyhelper")
	for _, dir := range []string{aDir, bDir, helperDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	a := &Project{ID: "p-a", Name: "a", Dir: aDir, OwnershipRoot: aDir, ComponentID: "c-a", Ecosystem: "node"}
	b := &Project{ID: "p-b", Name: "b", Dir: bDir, OwnershipRoot: bDir, ComponentID: "c-b", Ecosystem: "node"}
	libs := &Project{ID: "p-libs", Name: "libs", Dir: libsDir, OwnershipRoot: libsDir, ComponentID: "c-libs", Ecosystem: "node"}
	helper := &Project{ID: "p-helper", Name: "pyhelper", Dir: helperDir, OwnershipRoot: helperDir, ComponentID: "c-helper", Ecosystem: "python"}
	targetA := &Target{ID: "t-a", Name: "a", Project: a, Included: []*Project{a, libs}, IncludedReasons: map[string]InclusionReason{aDir: InclusionPrimary, libsDir: InclusionSharedDependency}, ComponentID: "c-a"}
	targetB := &Target{ID: "t-b", Name: "b", Project: b, Included: []*Project{b, libs, helper}, IncludedReasons: map[string]InclusionReason{bDir: InclusionPrimary, libsDir: InclusionSharedDependency, helperDir: InclusionSharedDependency}, ComponentID: "c-b"}
	resolution := &Resolution{
		RepoRoot: root,
		Projects: []*Project{a, b, libs, helper},
		Targets:  []*Target{targetA, targetB},
		Inventory: []InventoryEntry{
			{Path: "a/package-lock.json", Lockfile: true},
			{Path: "b/package-lock.json", Lockfile: true},
			{Path: "libs/package-lock.json", Lockfile: true},
			{Path: "uv.lock", Lockfile: true},
		},
	}

	for _, tc := range []struct {
		name    string
		options PlanOptions
		want    []string
	}{
		{"all targets", PlanOptions{AllTargets: true}, []string{"t-b"}},
		{"only the target that needs it", PlanOptions{TargetIDs: []string{"t-b"}}, []string{"t-b"}},
		{"only a target that does not", PlanOptions{TargetIDs: []string{"t-a"}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := BuildScanPlan(resolution, tc.options)
			if err != nil {
				t.Fatal(err)
			}
			fo := plan.FileOwnership["uv.lock"]
			var got []string
			if fo != nil {
				got = fo.TargetIDs
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("uv.lock TargetIDs = %v, want %v", got, tc.want)
			}
		})
	}
}

// A selected target whose root sits inside another selected target's root is
// folded into the enclosing unit. It must keep that unit (so its summary
// still names a scan unit) and its own fallback needs; the enclosing target
// must not inherit lockfiles for an ecosystem it does not use.
func TestBuildScanPlan_FoldedNestedTargetKeepsUnitAndFallback(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	toolDir := filepath.Join(appDir, "pytool")
	if err := os.MkdirAll(toolDir, 0o755); err != nil {
		t.Fatal(err)
	}
	app := &Project{ID: "p-app", Name: "app", Dir: appDir, OwnershipRoot: appDir, ComponentID: "c-app", Ecosystem: "node"}
	tool := &Project{ID: "p-tool", Name: "pytool", Dir: toolDir, OwnershipRoot: toolDir, ComponentID: "c-tool", Ecosystem: "python"}
	targetApp := &Target{ID: "t-app", Name: "app", Project: app, Included: []*Project{app}, IncludedReasons: map[string]InclusionReason{appDir: InclusionPrimary}, ComponentID: "c-app"}
	targetTool := &Target{ID: "t-tool", Name: "pytool", Project: tool, Included: []*Project{tool}, IncludedReasons: map[string]InclusionReason{toolDir: InclusionPrimary}, ComponentID: "c-tool"}
	resolution := &Resolution{
		RepoRoot: root,
		Projects: []*Project{app, tool},
		Targets:  []*Target{targetApp, targetTool},
		Inventory: []InventoryEntry{
			{Path: "app/package-lock.json", Lockfile: true},
			{Path: "uv.lock", Lockfile: true},
		},
	}
	plan, err := BuildScanPlan(resolution, PlanOptions{AllTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Units) != 1 {
		t.Fatalf("scan units = %d, want 1 (pytool folds into app)", len(plan.Units))
	}
	unit := plan.Units[0]
	if strings.Join(unit.TargetIDs, ",") != "t-app,t-tool" {
		t.Errorf("unit TargetIDs = %v, want both targets", unit.TargetIDs)
	}
	if unit.Relations["t-tool"] != RelationDirect {
		t.Errorf("folded target relation = %q, want %q", unit.Relations["t-tool"], RelationDirect)
	}
	if fo := plan.FileOwnership["uv.lock"]; fo == nil || strings.Join(fo.TargetIDs, ",") != "t-tool" {
		t.Errorf("uv.lock ownership = %+v, want only t-tool", fo)
	}
}

// A target reaching one unit both as its own project and through a folded
// nested dependency keeps its strongest relation, direct: a repository-root
// target whose shared library lives below it must still have the root unit
// scan its dependencies.
func TestBuildScanPlan_FoldedDependencyKeepsDirectRelation(t *testing.T) {
	root := t.TempDir()
	libDir := filepath.Join(root, "lib")
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatal(err)
	}
	server := &Project{ID: "p-server", Name: "server", Dir: root, OwnershipRoot: root, ComponentID: "c-server", Ecosystem: "node"}
	lib := &Project{ID: "p-lib", Name: "lib", Dir: libDir, OwnershipRoot: libDir, ComponentID: "c-lib", Ecosystem: "node"}
	target := &Target{ID: "t", Name: "server", Project: server, Included: []*Project{server, lib}, IncludedReasons: map[string]InclusionReason{root: InclusionPrimary, libDir: InclusionSharedDependency}, ComponentID: "c-server"}
	resolution := &Resolution{RepoRoot: root, Projects: []*Project{server, lib}, Targets: []*Target{target}}

	plan, err := BuildScanPlan(resolution, PlanOptions{AllTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Units) != 1 {
		t.Fatalf("scan units = %d, want 1 (lib folds into the root unit)", len(plan.Units))
	}
	if got := plan.Units[0].Relations["t"]; got != RelationDirect {
		t.Errorf("root unit relation = %q, want %q", got, RelationDirect)
	}
	if !plan.Units[0].ScansDependencies(root) {
		t.Error("the root unit of a repository-root target must scan dependencies")
	}
}

// Whether a project is already pinned is decided per project: a nested
// target's own lockfile pins that target, not the one enclosing it, while a
// lockfile in an enclosing workspace root inside the unit does pin the
// members beneath it.
func TestWorkspaceRootFallback_OwnLockfileIsDecidedPerProject(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	pluginDir := filepath.Join(appDir, "plugins", "b")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	app := &Project{ID: "p-a", Name: "a", Dir: appDir, OwnershipRoot: appDir, ComponentID: "c-a", Ecosystem: "node"}
	plugin := &Project{ID: "p-b", Name: "b", Dir: pluginDir, OwnershipRoot: pluginDir, ComponentID: "c-b", Ecosystem: "node"}
	targetA := &Target{ID: "t-a", Name: "a", Project: app, Included: []*Project{app}, IncludedReasons: map[string]InclusionReason{appDir: InclusionPrimary}, ComponentID: "c-a"}
	targetB := &Target{ID: "t-b", Name: "b", Project: plugin, Included: []*Project{plugin}, IncludedReasons: map[string]InclusionReason{pluginDir: InclusionPrimary}, ComponentID: "c-b"}

	for _, tc := range []struct {
		name      string
		inventory []InventoryEntry
		options   PlanOptions
		want      string // comma-separated targets credited with the root package-lock.json
	}{
		{"nested target's lockfile does not pin the enclosing target",
			[]InventoryEntry{{Path: "app/plugins/b/package-lock.json", Lockfile: true}, {Path: "package-lock.json", Lockfile: true}},
			PlanOptions{AllTargets: true}, "t-a"},
		{"same answer with only the enclosing target selected",
			[]InventoryEntry{{Path: "app/plugins/b/package-lock.json", Lockfile: true}, {Path: "package-lock.json", Lockfile: true}},
			PlanOptions{TargetIDs: []string{"t-a"}}, "t-a"},
		{"enclosing workspace lockfile pins the nested member",
			[]InventoryEntry{{Path: "app/package-lock.json", Lockfile: true}, {Path: "package-lock.json", Lockfile: true}},
			PlanOptions{AllTargets: true}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolution := &Resolution{RepoRoot: root, Projects: []*Project{app, plugin}, Targets: []*Target{targetA, targetB}, Inventory: tc.inventory}
			plan, err := BuildScanPlan(resolution, tc.options)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			if fo := plan.FileOwnership["package-lock.json"]; fo != nil {
				got = fo.TargetIDs
			}
			if strings.Join(got, ",") != tc.want {
				t.Errorf("package-lock.json credited to %v, want %q", got, tc.want)
			}
		})
	}
}

// Only lockfiles a package manager writes for a whole workspace can stand in
// for a nested project's missing one; a root poetry.lock or a dev/docs
// requirements file describes something else entirely.
func TestWorkspaceRootFallback_OnlyWorkspaceLockfilesQualify(t *testing.T) {
	root := t.TempDir()
	pyDir := filepath.Join(root, "servers", "py")
	if err := os.MkdirAll(pyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	project := &Project{ID: "p-py", Name: "py", Dir: pyDir, OwnershipRoot: pyDir, ComponentID: "c-py", Ecosystem: "python"}
	target := &Target{ID: "t-py", Name: "py", Project: project, Included: []*Project{project}, IncludedReasons: map[string]InclusionReason{pyDir: InclusionPrimary}}
	resolution := &Resolution{
		RepoRoot: root,
		Projects: []*Project{project},
		Targets:  []*Target{target},
		Inventory: []InventoryEntry{
			{Path: "poetry.lock", Lockfile: true},
			{Path: "requirements-dev.txt", Lockfile: true},
			{Path: "requirements-docs.txt", Lockfile: true},
			{Path: "requirements.txt", Lockfile: true},
			{Path: "uv.lock", Lockfile: true},
		},
	}
	plan, err := BuildScanPlan(resolution, PlanOptions{AllTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := fallbackNames(plan.Units[0]); got != "uv.lock" {
		t.Errorf("FallbackLockfiles = %v, want [uv.lock]", got)
	}
}

func TestBuildScanPlan_TargetIDValidation(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "server")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	project := &Project{ID: "p", Name: "server", Dir: dir, OwnershipRoot: dir, ComponentID: "c"}
	target := &Target{ID: "t-server", Name: "server", Project: project, Included: []*Project{project}, IncludedReasons: map[string]InclusionReason{dir: InclusionPrimary}}
	resolution := &Resolution{RepoRoot: root, Projects: []*Project{project}, Targets: []*Target{target}}

	if _, err := BuildScanPlan(resolution, PlanOptions{TargetIDs: []string{"t-server"}, AllTargets: true}); err != nil {
		t.Errorf("a discovered ID combined with AllTargets must be accepted, got %v", err)
	}
	_, err := BuildScanPlan(resolution, PlanOptions{TargetIDs: []string{"t-server", "t-missing"}, AllTargets: true})
	if err == nil || !strings.Contains(err.Error(), "t-missing") || strings.Contains(err.Error(), "t-server") {
		t.Errorf("error = %v, want it to name only the undiscovered ID t-missing", err)
	}
}

func TestBuildComponentRelations(t *testing.T) {
	dirA := filepath.Join(string(filepath.Separator), "repo", "a")
	dirB := filepath.Join(string(filepath.Separator), "repo", "b")
	dirShared := filepath.Join(string(filepath.Separator), "repo", "shared")
	dirTests := filepath.Join(string(filepath.Separator), "repo", "tests")
	targets := []*Target{
		{
			ID:      "t1",
			Name:    "server-a",
			Project: &Project{ID: "p1", Dir: dirA, ComponentID: "c-a"},
			Included: []*Project{
				{ID: "p1", Dir: dirA, ComponentID: "c-a"},
				{ID: "ps", Dir: dirShared, ComponentID: "c-shared"},
			},
			IncludedReasons: map[string]InclusionReason{filepath.Clean(dirA): InclusionPrimary, filepath.Clean(dirShared): InclusionSharedDependency},
		},
		{
			ID:      "t2",
			Name:    "server-b",
			Project: &Project{ID: "p2", Dir: dirB, ComponentID: "c-b"},
			Included: []*Project{
				{ID: "p2", Dir: dirB, ComponentID: "c-b"},
				{ID: "ps", Dir: dirShared, ComponentID: "c-shared"},
				{ID: "pt", Dir: dirTests, ComponentID: "c-tests"},
			},
			IncludedReasons: map[string]InclusionReason{filepath.Clean(dirB): InclusionPrimary, filepath.Clean(dirShared): InclusionSharedDependency, filepath.Clean(dirTests): InclusionTestDependent},
		},
	}
	relations := buildComponentRelations(targets)
	if relations["c-a"] != RelationDirect {
		t.Errorf("c-a = %q, want direct", relations["c-a"])
	}
	if relations["c-b"] != RelationDirect {
		t.Errorf("c-b = %q, want direct", relations["c-b"])
	}
	if relations["c-shared"] != RelationShared {
		t.Errorf("c-shared = %q, want shared (used by two targets)", relations["c-shared"])
	}
	if relations["c-tests"] != RelationCompanion {
		t.Errorf("c-tests = %q, want companion", relations["c-tests"])
	}
}

// OwnershipOf accepts the absolute paths scanners report as well as
// repository-relative ones, and treats a file the plan never inventoried as
// repository-global content classified by its own path.
func TestOwnershipOf(t *testing.T) {
	repoRoot := t.TempDir()
	plan := &ScanPlan{
		RepoRoot: repoRoot,
		FileOwnership: map[string]*FileOwnership{
			"src/main.go": {TargetIDs: []string{"t1"}, ComponentIDs: []string{"c1"}, Relation: RelationDirect, Context: "production"},
		},
	}
	for _, path := range []string{"src/main.go", filepath.Join(repoRoot, "src", "main.go")} {
		fo := plan.OwnershipOf(path)
		if fo.Relation != RelationDirect || len(fo.TargetIDs) != 1 || fo.TargetIDs[0] != "t1" {
			t.Errorf("OwnershipOf(%q) = %+v, want the src/main.go record", path, fo)
		}
	}
	for path, context := range map[string]string{"unknown/path.go": "production", "docs/guide.md": "docs", "tests/unit_test.go": "test"} {
		fo := plan.OwnershipOf(path)
		if fo.Relation != RelationRepositoryGlobal || len(fo.TargetIDs) != 0 {
			t.Errorf("OwnershipOf(%q) = %+v, want an unowned repository-global record", path, fo)
		}
		if fo.Context != context {
			t.Errorf("OwnershipOf(%q).Context = %q, want %q", path, fo.Context, context)
		}
	}
}

func TestBuildFileOwnershipWithMultipleTargets(t *testing.T) {
	resolution := &Resolution{
		RepoRoot: "/repo",
		Inventory: []InventoryEntry{
			{Path: "shared/util.go", ComponentIDs: []string{"c-shared"}},
			{Path: "a/main.go", ComponentIDs: []string{"c-a"}},
			{Path: "README.md", ComponentIDs: nil},
		},
	}
	targets := []*Target{
		{
			ID:      "t1",
			Project: &Project{ComponentID: "c-a"},
			Included: []*Project{
				{ComponentID: "c-a"},
				{ComponentID: "c-shared"},
			},
		},
		{
			ID:      "t2",
			Project: &Project{ComponentID: "c-b"},
			Included: []*Project{
				{ComponentID: "c-b"},
				{ComponentID: "c-shared"},
			},
		},
	}
	relations := map[string]Relation{"c-a": RelationDirect, "c-b": RelationDirect, "c-shared": RelationShared}
	ownership := buildFileOwnership(resolution, relations, targets)

	if fo := ownership["shared/util.go"]; fo == nil {
		t.Fatal("shared/util.go missing from ownership")
	} else {
		if len(fo.TargetIDs) != 2 {
			t.Errorf("shared/util.go targets = %v, want 2 targets", fo.TargetIDs)
		}
		if fo.Relation != RelationShared {
			t.Errorf("shared/util.go relation = %q, want shared", fo.Relation)
		}
	}

	if fo := ownership["a/main.go"]; fo == nil {
		t.Fatal("a/main.go missing from ownership")
	} else {
		if len(fo.TargetIDs) != 1 {
			t.Errorf("a/main.go targets = %v, want 1", fo.TargetIDs)
		}
		if fo.Relation != RelationDirect {
			t.Errorf("a/main.go relation = %q, want direct", fo.Relation)
		}
	}

	if fo := ownership["README.md"]; fo == nil {
		t.Fatal("README.md missing from ownership")
	} else {
		if fo.Relation != RelationRepositoryGlobal {
			t.Errorf("README.md relation = %q, want repository-global", fo.Relation)
		}
		if fo.Context != "docs" {
			t.Errorf("README.md context = %q, want docs", fo.Context)
		}
	}
}

// File contexts recorded in the scan plan's ownership map are what every
// finding is labeled with; a file named like a context tag is still
// production code unless a directory says otherwise.
func TestBuildScanPlan_FileOwnershipContexts(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "server")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	project := &Project{ID: "p", Name: "server", Dir: dir, OwnershipRoot: dir, ComponentID: "c"}
	target := &Target{ID: "t", Name: "server", Project: project, Included: []*Project{project}, IncludedReasons: map[string]InclusionReason{dir: InclusionPrimary}, ComponentID: "c"}
	want := map[string]string{
		"server/src/test.go":           "production",
		"server/src/tools.ts":          "production",
		"server/internal/security.go":  "production",
		"server/tests/server_test.go":  "test",
		"server/SECURITY.md":           "docs",
		"server/vendor/x/testing/y.go": "vendored",
	}
	var inventory []InventoryEntry
	for path := range want {
		inventory = append(inventory, InventoryEntry{Path: path, ProjectIDs: []string{"p"}, ComponentIDs: []string{"c"}})
	}
	resolution := &Resolution{RepoRoot: root, Projects: []*Project{project}, Targets: []*Target{target}, Inventory: inventory}
	plan, err := BuildScanPlan(resolution, PlanOptions{AllTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	for path, context := range want {
		if fo := plan.FileOwnership[path]; fo == nil || fo.Context != context {
			t.Errorf("FileOwnership[%q] = %+v, want context %q", path, fo, context)
		}
		if got := plan.OwnershipOf(path).Context; got != context {
			t.Errorf("OwnershipOf(%q).Context = %q, want %q", path, got, context)
		}
	}
}

func TestResolveStableIDsAndOwnershipAboveNestedManifest(t *testing.T) {
	root := t.TempDir()
	component := filepath.Join(root, "component")
	manifestDir := filepath.Join(component, "src")
	writeFile(t, filepath.Join(component, "server.json"), `{"name":"example/server","packages":[{"registryType":"npm","identifier":"example"}]}`)
	writeFile(t, filepath.Join(manifestDir, "package.json"), `{"name":"server","dependencies":{"@modelcontextprotocol/sdk":"^1"}}`)
	writeFile(t, filepath.Join(manifestDir, "index.js"), `const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js"); new McpServer();`)
	writeFile(t, filepath.Join(component, "README.md"), "owned docs")
	first, err := Resolve(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Resolve(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(first.Targets))
	}
	if first.Targets[0].ID == "" || first.Targets[0].Project.ID == "" || first.Targets[0].Project.ComponentID == "" {
		t.Fatal("expected stable project/component/target IDs")
	}
	if first.Targets[0].ID != second.Targets[0].ID {
		t.Errorf("target ID changed: %q vs %q", first.Targets[0].ID, second.Targets[0].ID)
	}
	if filepath.Clean(first.Targets[0].Project.OwnershipRoot) != filepath.Clean(component) {
		t.Fatalf("ownership root = %q, want %q", first.Targets[0].Project.OwnershipRoot, component)
	}
	roots := first.Targets[0].ScanRoots()
	if len(roots) != 1 || filepath.Clean(roots[0]) != filepath.Clean(component) {
		t.Fatalf("scan roots = %v, want component root", roots)
	}
}

// fallbackNames returns unit's fallback lockfile names, sorted and
// comma-separated, for compact assertions.
func fallbackNames(unit *ScanUnit) string {
	names := make([]string, 0, len(unit.FallbackLockfiles))
	for name := range unit.FallbackLockfiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// A unit below the repository root always scans dependencies; the unit at
// the root only does when a selected target's own project lives there, since
// otherwise the root's dependency files belong to no selected target.
func TestScanUnit_ScansDependencies(t *testing.T) {
	repoRoot := t.TempDir()
	cases := []struct {
		name string
		unit ScanUnit
		want bool
	}{
		{"nested unit", ScanUnit{Root: filepath.Join(repoRoot, "server"), Relations: map[string]Relation{"t": RelationShared}}, true},
		{"root unit of a root-level target", ScanUnit{Root: repoRoot, Relations: map[string]Relation{"t": RelationDirect}}, true},
		{"repository-global root unit", ScanUnit{Root: repoRoot, Relations: map[string]Relation{"t": RelationRepositoryGlobal}}, false},
	}
	for _, tc := range cases {
		if got := tc.unit.ScansDependencies(repoRoot); got != tc.want {
			t.Errorf("%s: ScansDependencies() = %v, want %v", tc.name, got, tc.want)
		}
	}
}
