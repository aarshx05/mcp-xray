package targetresolve

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"mcpxray/internal/aggregation"
)

// Relation is how a scan unit or a file relates to a selected target.
type Relation string

const (
	// RelationDirect: the target's own project (for a unit), or a file only
	// one selected target uses (for a file).
	RelationDirect Relation = "direct"
	// RelationShared: a dependency of the target (for a unit), or a file
	// several selected targets use (for a file).
	RelationShared Relation = "shared"
	// RelationCompanion: a test project that depends on the target.
	RelationCompanion Relation = "companion"
	// RelationRepositoryGlobal: repository content no selected target owns.
	RelationRepositoryGlobal Relation = "repository-global"
	// RelationWorkspaceRoot: a repository-root lockfile scanned on a target's
	// behalf (see ScanUnit.FallbackLockfiles).
	RelationWorkspaceRoot Relation = "workspace-root-dependency"
)

// rank orders relations by how closely they tie content to a target, so the
// strongest wins when several apply.
func (r Relation) rank() int {
	switch r {
	case RelationDirect:
		return 4
	case RelationCompanion:
		return 3
	case RelationShared:
		return 2
	case RelationRepositoryGlobal:
		return 1
	}
	return 0
}

// ScanUnit is one physical scanner invocation. A unit may serve several
// targets, but its root is scanned only once.
type ScanUnit struct {
	ID           string              `json:"id"`
	Root         string              `json:"-"`
	RelativeRoot string              `json:"root"`
	TargetIDs    []string            `json:"targetIds,omitempty"`
	Relations    map[string]Relation `json:"relations,omitempty"`
	ExcludedDirs []string            `json:"excludedDirs,omitempty"`
	Files        []string            `json:"files,omitempty"`
	Manifests    []string            `json:"manifests,omitempty"`
	Lockfiles    []string            `json:"lockfiles,omitempty"`

	// FallbackLockfiles maps each repository-root lockfile that dependency
	// scanning must also read on this unit's behalf to the IDs of the
	// targets relying on it. It is the shared-workspace-lockfile pattern: a
	// workspace member declares its dependencies in its own manifest, but
	// only the workspace root's lockfile pins their versions. Empty for a
	// unit rooted at the repository root, which scans those files itself.
	FallbackLockfiles map[string][]string `json:"fallbackLockfiles,omitempty"`
}

// ScansDependencies reports whether dependency (SCA) scanning runs on the
// unit. A unit rooted at the repository root scans dependencies only when a
// selected target's own project lives there; otherwise the root's
// dependency files belong to no selected target.
func (u *ScanUnit) ScansDependencies(repoRoot string) bool {
	if filepath.Clean(u.Root) != filepath.Clean(repoRoot) {
		return true
	}
	for _, relation := range u.Relations {
		if relation == RelationDirect {
			return true
		}
	}
	return false
}

// PlanOptions selects the targets to plan and the paths to keep out of
// every scan.
type PlanOptions struct {
	TargetIDs         []string
	AllTargets        bool
	IncludeRepoGlobal bool
	OutputPath        string
	OutputDirs        []string
}

// ScanPlan is the set of scan units that together cover the selected
// targets, and the ownership of every inventoried file.
type ScanPlan struct {
	RepoRoot        string
	SelectedTargets []*Target
	Units           []*ScanUnit
	Inventory       []InventoryEntry
	Excluded        []string
	Unowned         []string
	Ambiguous       []string
	FileOwnership   map[string]*FileOwnership
}

// TargetPlanView is a selected target as shown in ScanPlanView.
type TargetPlanView struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	ComponentID        string   `json:"componentId"`
	IncludedProjectIDs []string `json:"includedProjectIds"`
}

// ScanPlanView is the machine-readable form of a ScanPlan, with
// repository-relative paths.
type ScanPlanView struct {
	RepoRoot        string           `json:"repoRoot"`
	SelectedTargets []TargetPlanView `json:"selectedTargets"`
	Units           []*ScanUnit      `json:"scanUnits"`
	Inventory       []InventoryEntry `json:"inventory"`
	Excluded        []string         `json:"excluded,omitempty"`
	Unowned         []string         `json:"unowned,omitempty"`
	Ambiguous       []string         `json:"ambiguous,omitempty"`
}

// StructuredScanPlan returns the machine-readable view of plan.
func StructuredScanPlan(plan *ScanPlan) ScanPlanView {
	view := ScanPlanView{RepoRoot: ".", Units: plan.Units, Inventory: plan.Inventory, Excluded: plan.Excluded, Unowned: plan.Unowned, Ambiguous: plan.Ambiguous}
	for _, target := range plan.SelectedTargets {
		view.SelectedTargets = append(view.SelectedTargets, TargetPlanView{ID: target.ID, Name: target.Name, ComponentID: target.ComponentID, IncludedProjectIDs: target.IncludedProjectIDs})
	}
	return view
}

// buildInventory lists every file under repoRoot the scanners would see,
// flags dependency manifests and lockfiles, and records which projects'
// (and components') scan roots contain each file. MCP X-Ray's own generated
// reports are returned separately as excluded.
func buildInventory(repoRoot string, projects []*Project) ([]InventoryEntry, []string, error) {
	var inventory []InventoryEntry
	var excluded []string
	err := walkFiles(repoRoot, nil, func(path string, info os.FileInfo) error {
		rel := repoRelative(repoRoot, path)
		if isGeneratedOutputPath(path) {
			excluded = append(excluded, rel)
			return nil
		}
		entry := InventoryEntry{Path: rel, Manifest: matchesManifest(info.Name()), Lockfile: matchesLockfile(info.Name()), Ownership: "unowned"}
		for _, p := range projects {
			if root := p.ScanRoot(); within(path, root) {
				entry.ProjectIDs = append(entry.ProjectIDs, p.ID)
				entry.ComponentIDs = append(entry.ComponentIDs, p.ComponentID)
				if entry.Ownership == "unowned" {
					entry.Ownership = repoRelative(repoRoot, root)
				}
			}
		}
		entry.ProjectIDs = uniqueSorted(entry.ProjectIDs)
		entry.ComponentIDs = uniqueSorted(entry.ComponentIDs)
		inventory = append(inventory, entry)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(inventory, func(i, j int) bool { return inventory[i].Path < inventory[j].Path })
	sort.Strings(excluded)
	return inventory, excluded, nil
}

// isGeneratedOutputPath reports whether path is a report MCP X-Ray writes.
func isGeneratedOutputPath(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	for _, prefix := range []string{"findings-", "findings_", "merged-", "merged_", "tools_summary_", "merged_test_plan"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return strings.HasSuffix(name, ".sarif.json") && (strings.Contains(name, "mcpxray") || strings.Contains(name, "repo-scan"))
}

func within(path, root string) bool {
	path, root = filepath.Clean(path), filepath.Clean(root)
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

// BuildScanPlan creates one scan unit per scan root of the selected targets
// (nested roots folded into the root enclosing them), plus the residual
// repository-global unit when requested, and records which targets own
// every inventoried file.
func BuildScanPlan(resolution *Resolution, options PlanOptions) (*ScanPlan, error) {
	if resolution == nil {
		return nil, fmt.Errorf("resolution is nil")
	}
	selected, err := selectTargets(resolution.Targets, options)
	if err != nil {
		return nil, err
	}

	units, roots := unitsForTargets(resolution.RepoRoot, selected)
	if options.IncludeRepoGlobal && !containsRoot(roots, filepath.Clean(resolution.RepoRoot)) {
		units = append(units, repositoryGlobalUnit(resolution.RepoRoot, selected, roots))
	}
	includedRoots := includedScanRoots(selected)
	for _, unit := range units {
		finalizeUnit(unit, resolution, selected, includedRoots, options)
	}
	sort.Slice(units, func(i, j int) bool { return units[i].ID < units[j].ID })

	plan := &ScanPlan{RepoRoot: resolution.RepoRoot, SelectedTargets: selected, Units: units, Inventory: resolution.Inventory}
	for _, entry := range plan.Inventory {
		if entry.Ownership == "unowned" {
			plan.Unowned = append(plan.Unowned, entry.Path)
		}
	}
	plan.Excluded = uniqueSorted(append(append([]string(nil), resolution.Excluded...), generatedRelativeExcludes(resolution.RepoRoot, options)...))
	for _, project := range resolution.Projects {
		if project.OwnershipAmbiguous {
			plan.Ambiguous = append(plan.Ambiguous, project.ID)
		}
	}
	sort.Strings(plan.Ambiguous)
	plan.FileOwnership = buildFileOwnership(resolution, buildComponentRelations(selected), selected)
	applyWorkspaceRootFallbackOwnership(plan, selected)
	return plan, nil
}

// selectTargets returns the targets options asks for. Every requested ID
// must have been discovered, also when AllTargets selects them anyway.
func selectTargets(targets []*Target, options PlanOptions) ([]*Target, error) {
	requested := make(map[string]bool)
	for _, id := range options.TargetIDs {
		requested[id] = true
	}
	selected := make([]*Target, 0)
	discovered := make(map[string]bool, len(targets))
	for _, target := range targets {
		discovered[target.ID] = true
		if options.AllTargets || requested[target.ID] {
			selected = append(selected, target)
		}
	}
	var unknown []string
	for id := range requested {
		if !discovered[id] {
			unknown = append(unknown, id)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf("target ID(s) not discovered: %q", unknown)
	}
	if len(selected) == 0 && !options.AllTargets {
		return nil, fmt.Errorf("no targets selected")
	}
	return selected, nil
}

// unitsForTargets creates one unit per scan root of the selected targets'
// included projects. A unit whose root lies inside another unit's root is
// folded into that enclosing unit, whose recursive scan already covers its
// files; its targets carry over so they keep a unit (and their own
// workspace-root fallback). roots are the remaining, non-nested unit roots.
func unitsForTargets(repoRoot string, selected []*Target) (units []*ScanUnit, roots []string) {
	byRoot := make(map[string]*ScanUnit)
	for _, target := range selected {
		for _, project := range target.Included {
			root := project.ScanRoot()
			unit := byRoot[root]
			if unit == nil {
				rel := repoRelative(repoRoot, root)
				unit = &ScanUnit{ID: stableID("scan", rel), Root: root, RelativeRoot: rel, Relations: map[string]Relation{}}
				byRoot[root] = unit
				roots = append(roots, root)
			}
			unit.addTarget(target.ID, target.relationOf(project))
		}
	}
	roots = dropNestedRoots(roots)
	for _, root := range roots {
		units = append(units, byRoot[root])
	}
	for root, unit := range byRoot {
		if containsRoot(roots, root) {
			continue
		}
		for _, enclosing := range roots {
			if within(root, enclosing) {
				for _, targetID := range unit.TargetIDs {
					byRoot[enclosing].addTarget(targetID, unit.Relations[targetID])
				}
				break
			}
		}
	}
	return units, roots
}

// addTarget records that the unit serves targetID, keeping the strongest
// relation when the target reaches the unit more than once.
func (u *ScanUnit) addTarget(targetID string, relation Relation) {
	u.TargetIDs = appendUniqueStr(u.TargetIDs, targetID)
	if relation.rank() > u.Relations[targetID].rank() {
		u.Relations[targetID] = relation
	}
}

// relationOf is how one of the target's included projects relates to it.
func (t *Target) relationOf(p *Project) Relation {
	switch {
	case p == t.Project:
		return RelationDirect
	case t.IncludedReasons[filepath.Clean(p.Dir)] == InclusionTestDependent:
		return RelationCompanion
	}
	return RelationShared
}

// repositoryGlobalUnit covers the repository content outside every scheduled
// root, once, for all selected targets. It excludes only those roots, so
// discovered-but-unselected projects stay visible to it.
func repositoryGlobalUnit(repoRoot string, selected []*Target, roots []string) *ScanUnit {
	unit := &ScanUnit{ID: stableID("scan", "."), Root: repoRoot, RelativeRoot: ".", Relations: map[string]Relation{}, ExcludedDirs: residualExcludes(repoRoot, roots)}
	for _, target := range selected {
		unit.addTarget(target.ID, RelationRepositoryGlobal)
	}
	return unit
}

// includedScanRoots is every scan root any selected target includes. A unit
// may have absorbed another target's nested root, so foreign-project
// exclusion must consult all of them, not just the unit's own.
func includedScanRoots(selected []*Target) map[string]bool {
	roots := make(map[string]bool)
	for _, target := range selected {
		for _, project := range target.Included {
			roots[project.ScanRoot()] = true
		}
	}
	return roots
}

// finalizeUnit fills in the unit's file lists and exclusions: generated
// reports and, for a unit below the repository root, every discovered
// project nested in it that no selected target includes. It then decides
// which repository-root lockfiles the unit's targets need.
func finalizeUnit(unit *ScanUnit, resolution *Resolution, selected []*Target, includedRoots map[string]bool, options PlanOptions) {
	sort.Strings(unit.TargetIDs)
	unit.Files, unit.Manifests, unit.Lockfiles = unitFiles(resolution.RepoRoot, unit.Root, resolution.Inventory)
	unit.ExcludedDirs = append(unit.ExcludedDirs, generatedRelativeExcludes(unit.Root, options)...)
	atRepoRoot := filepath.Clean(unit.Root) == filepath.Clean(resolution.RepoRoot)
	if !atRepoRoot {
		unit.ExcludedDirs = append(unit.ExcludedDirs, nestedForeignExcludes(unit.Root, includedRoots, resolution.Projects)...)
	}
	for _, excluded := range resolution.Excluded {
		abs := filepath.Join(resolution.RepoRoot, filepath.FromSlash(excluded))
		if within(abs, unit.Root) && abs != filepath.Clean(unit.Root) {
			unit.ExcludedDirs = append(unit.ExcludedDirs, repoRelative(unit.Root, abs))
		}
	}
	unit.ExcludedDirs = uniqueSorted(unit.ExcludedDirs)
	if !atRepoRoot {
		unit.FallbackLockfiles = workspaceRootFallbackLockfiles(resolution, selected, unit)
	}
}

// buildComponentRelations gives each component used by a selected target its
// relation: shared when several selected targets use it, companion when its
// only user includes it as a test dependent, direct otherwise.
func buildComponentRelations(targets []*Target) map[string]Relation {
	usage := make(map[string]map[string]InclusionReason)
	for _, target := range targets {
		for _, project := range target.Included {
			cid := project.ComponentID
			if usage[cid] == nil {
				usage[cid] = make(map[string]InclusionReason)
			}
			reason := target.IncludedReasons[filepath.Clean(project.Dir)]
			if reason.rank() > usage[cid][target.ID].rank() {
				usage[cid][target.ID] = reason
			}
		}
	}

	relations := make(map[string]Relation, len(usage))
	for cid, targetReasons := range usage {
		relations[cid] = RelationDirect
		if len(targetReasons) > 1 {
			relations[cid] = RelationShared
			continue
		}
		for _, reason := range targetReasons {
			if reason == InclusionTestDependent {
				relations[cid] = RelationCompanion
			}
		}
	}
	return relations
}

// buildFileOwnership records, for every inventoried file (keyed by its
// repository-relative POSIX path), the components and selected targets that
// own it, its strongest relation to them and its context.
func buildFileOwnership(resolution *Resolution, componentRelations map[string]Relation, targets []*Target) map[string]*FileOwnership {
	componentTargets := make(map[string][]string)
	for _, target := range targets {
		for _, project := range target.Included {
			cid := project.ComponentID
			componentTargets[cid] = appendUniqueStr(componentTargets[cid], target.ID)
		}
	}

	ownership := make(map[string]*FileOwnership, len(resolution.Inventory))
	for _, entry := range resolution.Inventory {
		fo := &FileOwnership{
			ComponentIDs: entry.ComponentIDs,
			Relation:     RelationRepositoryGlobal,
			Context:      aggregation.ContextForPath(entry.Path),
		}
		for _, cid := range entry.ComponentIDs {
			fo.TargetIDs = appendUniqueStr(fo.TargetIDs, componentTargets[cid]...)
			if rel := componentRelations[cid]; rel.rank() > fo.Relation.rank() {
				fo.Relation = rel
			}
		}
		sort.Strings(fo.TargetIDs)
		sort.Strings(fo.ComponentIDs)
		ownership[entry.Path] = fo
	}
	return ownership
}

func appendUniqueStr(s []string, values ...string) []string {
	set := make(map[string]bool, len(s)+len(values))
	for _, v := range s {
		set[v] = true
	}
	for _, v := range values {
		if v != "" && !set[v] {
			set[v] = true
			s = append(s, v)
		}
	}
	return s
}

// OwnershipOf returns the ownership of file, given as an absolute path or
// relative to the repository root. A file outside the inventory belongs to
// no selected target.
func (p *ScanPlan) OwnershipOf(file string) FileOwnership {
	rel := file
	if filepath.IsAbs(file) {
		if r, err := filepath.Rel(p.RepoRoot, file); err == nil {
			rel = r
		}
	}
	rel = filepath.ToSlash(filepath.Clean(rel))
	if ownership := p.FileOwnership[rel]; ownership != nil {
		return *ownership
	}
	return FileOwnership{Relation: RelationRepositoryGlobal, Context: aggregation.ContextForPath(rel)}
}

// TargetSummaries describes every selected target -- including one with no
// findings -- with the units that scan it and its finding counts.
func (p *ScanPlan) TargetSummaries(rawFindings, uniqueFindings map[string]int) []TargetSummary {
	summaries := make([]TargetSummary, 0, len(p.SelectedTargets))
	for _, target := range p.SelectedTargets {
		var unitIDs []string
		for _, unit := range p.Units {
			if containsString(unit.TargetIDs, target.ID) {
				unitIDs = append(unitIDs, unit.ID)
			}
		}
		summaries = append(summaries, TargetSummary{
			TargetID:       target.ID,
			Name:           target.Name,
			ProjectID:      target.Project.ID,
			ComponentID:    target.ComponentID,
			OwnershipRoot:  repoRelative(p.RepoRoot, target.Project.ScanRoot()),
			ScanUnitIDs:    unitIDs,
			RawFindings:    rawFindings[target.ID],
			UniqueFindings: uniqueFindings[target.ID],
		})
	}
	return summaries
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func containsRoot(roots []string, wanted string) bool {
	for _, root := range roots {
		if filepath.Clean(root) == wanted {
			return true
		}
	}
	return false
}

func unitFiles(repoRoot, root string, inventory []InventoryEntry) ([]string, []string, []string) {
	var files, manifests, lockfiles []string
	for _, entry := range inventory {
		abs := filepath.Join(repoRoot, filepath.FromSlash(entry.Path))
		if !within(abs, root) {
			continue
		}
		files = append(files, entry.Path)
		if entry.Manifest {
			manifests = append(manifests, entry.Path)
		}
		if entry.Lockfile {
			lockfiles = append(lockfiles, entry.Path)
		}
	}
	return files, manifests, lockfiles
}

// isExcludedFromUnit reports whether abs (an absolute path already known to
// be within unit.Root) falls under one of unit's own finalized ExcludedDirs.
func isExcludedFromUnit(unit *ScanUnit, abs string) bool {
	rel, err := filepath.Rel(unit.Root, abs)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	for _, excluded := range unit.ExcludedDirs {
		if rel == excluded || strings.HasPrefix(rel, excluded+"/") {
			return true
		}
	}
	return false
}

// workspaceRootFallbackLockfiles returns each repo-root-level lockfile that
// must back up unit's own SCA scope, mapped to the IDs of the selected
// targets that need it. A target needs a root lockfile when a project it
// includes inside this unit (and not pruned from it) is not already pinned
// by a lockfile of its own ecosystem family (lockfilePinsProject), and that
// root lockfile can pin it (rootLockfileCanPin). The decision is made per
// project and per family: a Python package's uv.lock says nothing about the
// Node package next to it, and a nested project's own lockfile says nothing
// about the project enclosing it. Only projects a target actually includes
// count: anything else under the unit merely shares its directory (a client
// script beside a server, say) and must not pull unrelated lockfiles into
// that target's results.
func workspaceRootFallbackLockfiles(resolution *Resolution, selected []*Target, unit *ScanUnit) map[string][]string {
	var rootLockfiles, unitLockfiles []string
	for _, entry := range resolution.Inventory {
		if !entry.Lockfile {
			continue
		}
		abs := filepath.Join(resolution.RepoRoot, filepath.FromSlash(entry.Path))
		switch {
		case !strings.Contains(entry.Path, "/"):
			rootLockfiles = append(rootLockfiles, entry.Path) // only the repository root's own direct files qualify
		case within(abs, unit.Root) && !isExcludedFromUnit(unit, abs):
			unitLockfiles = append(unitLockfiles, abs) // only files that actually reach this unit's scanner
		}
	}
	if len(rootLockfiles) == 0 {
		return nil
	}
	var projectRoots []string
	for _, project := range resolution.Projects {
		projectRoots = append(projectRoots, project.ScanRoot())
	}

	needed := make(map[string][]string)
	for _, target := range selected {
		if !containsString(unit.TargetIDs, target.ID) {
			continue
		}
		for _, project := range target.Included {
			root := project.ScanRoot()
			if !within(root, unit.Root) || isExcludedFromUnit(unit, root) {
				continue
			}
			family := ecosystemFamily(project.Ecosystem)
			if family == "" || lockfilePinsProject(unitLockfiles, family, root, unit.Root, projectRoots) {
				continue
			}
			for _, lockfile := range rootLockfiles {
				if rootLockfileCanPin(lockfile, project.Ecosystem) {
					needed[lockfile] = appendUniqueStr(needed[lockfile], target.ID)
				}
			}
		}
	}
	if len(needed) == 0 {
		return nil
	}
	return needed
}

// lockfilePinsProject reports whether one of lockfiles (absolute paths) of
// the given ecosystem family pins the project rooted at root inside a unit
// rooted at unitRoot: a lockfile in root itself or in an enclosing directory
// within the unit (a workspace root above the project), or one deeper in the
// project's own tree that does not belong to another project nested there.
func lockfilePinsProject(lockfiles []string, family, root, unitRoot string, projectRoots []string) bool {
	for _, lockfile := range lockfiles {
		if lockfileEcosystem(filepath.Base(lockfile)) != family {
			continue
		}
		dir := filepath.Dir(lockfile)
		if within(root, dir) && within(dir, unitRoot) {
			return true // in the project's own directory or a workspace root above it
		}
		if within(lockfile, root) && !insideNestedProject(lockfile, root, projectRoots) {
			return true
		}
	}
	return false
}

// insideNestedProject reports whether path lies inside some project root
// nested strictly below root.
func insideNestedProject(path, root string, projectRoots []string) bool {
	for _, other := range projectRoots {
		if other != root && within(other, root) && within(path, other) {
			return true
		}
	}
	return false
}

// applyWorkspaceRootFallbackOwnership attributes each workspace-root
// fallback lockfile to exactly the targets that rely on it, merging into
// buildFileOwnership's record. The file sits outside every target's own
// tree, so without this its findings would belong to no target.
func applyWorkspaceRootFallbackOwnership(plan *ScanPlan, selected []*Target) {
	targetComponent := make(map[string]string, len(selected))
	for _, t := range selected {
		targetComponent[t.ID] = t.ComponentID
	}
	for _, unit := range plan.Units {
		for path, reliantTargetIDs := range unit.FallbackLockfiles {
			var targetIDs, componentIDs []string
			for _, tid := range reliantTargetIDs {
				targetIDs = appendUniqueStr(targetIDs, tid)
				if cid := targetComponent[tid]; cid != "" {
					componentIDs = appendUniqueStr(componentIDs, cid)
				}
			}
			fo := &FileOwnership{Relation: RelationWorkspaceRoot, Context: aggregation.ContextForPath(path)}
			if existing := plan.FileOwnership[path]; existing != nil {
				fo.TargetIDs = appendUniqueStr(append([]string{}, existing.TargetIDs...), targetIDs...)
				fo.ComponentIDs = appendUniqueStr(append([]string{}, existing.ComponentIDs...), componentIDs...)
			} else {
				fo.TargetIDs = targetIDs
				fo.ComponentIDs = componentIDs
			}
			sort.Strings(fo.TargetIDs)
			sort.Strings(fo.ComponentIDs)
			plan.FileOwnership[path] = fo
		}
	}
}

func generatedRelativeExcludes(repoRoot string, options PlanOptions) []string {
	var result []string
	for _, value := range append([]string{options.OutputPath}, options.OutputDirs...) {
		if value == "" {
			continue
		}
		abs, err := filepath.Abs(value)
		if err != nil {
			continue
		}
		if within(abs, repoRoot) && abs != filepath.Clean(repoRoot) {
			result = append(result, repoRelative(repoRoot, abs))
		}
	}
	return result
}
