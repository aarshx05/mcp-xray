package main

import (
	"path/filepath"
	"testing"

	"mcpxray/internal/targetresolve"
	"mcpxray/proto"
)

func TestReadTargetFlags(t *testing.T) {
	cases := []struct {
		name          string
		args          []string
		wantEnabled   bool
		wantExplicit  bool
		wantErrSubstr string
	}{
		{name: "no target flags keeps the full-repository scan", args: nil},
		{name: "--target alone enables target resolution", args: []string{"--target", "my-server"}, wantEnabled: true, wantExplicit: true},
		{name: "--target-id alone enables target resolution", args: []string{"--target-id", "t-1"}, wantEnabled: true, wantExplicit: true},
		{name: "--all-targets alone enables target resolution", args: []string{"--all-targets"}, wantEnabled: true, wantExplicit: true},
		{name: "--list-targets enables target resolution without selecting", args: []string{"--list-targets"}, wantEnabled: true},
		{name: "--list-targets --json is accepted", args: []string{"--list-targets", "--json"}, wantEnabled: true},
		{name: "--explain-scope enables target resolution without selecting", args: []string{"--explain-scope"}, wantEnabled: true},
		{name: "--include-repo-global enables target resolution without selecting", args: []string{"--include-repo-global"}, wantEnabled: true},
		{name: "--target-resolution enables target resolution without selecting", args: []string{"--target-resolution"}, wantEnabled: true},
		{name: "--output-dir alone keeps the full-repository scan", args: []string{"--output-dir", "out"}},
		{name: "--json needs --list-targets", args: []string{"--json"}, wantErrSubstr: "--json requires --list-targets"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := NewRepoScanCommand()
			if err := cmd.ParseFlags(tc.args); err != nil {
				t.Fatalf("ParseFlags(%v) failed: %v", tc.args, err)
			}
			got, err := readTargetFlags(cmd)
			if tc.wantErrSubstr != "" {
				if err == nil || err.Error() != tc.wantErrSubstr {
					t.Fatalf("readTargetFlags(%v) error = %v, want %q", tc.args, err, tc.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("readTargetFlags(%v) failed: %v", tc.args, err)
			}
			if got.enabled != tc.wantEnabled {
				t.Errorf("enabled = %v, want %v", got.enabled, tc.wantEnabled)
			}
			if got.explicitSelection() != tc.wantExplicit {
				t.Errorf("explicitSelection() = %v, want %v", got.explicitSelection(), tc.wantExplicit)
			}
		})
	}
}

// TestAttribute credits a finding to the targets its file's ownership names,
// and leaves a file no target owns unowned, which ownedByATarget then drops
// from the workspace-root dependency check.
func TestAttribute(t *testing.T) {
	repoRoot := t.TempDir()
	plan := &targetresolve.ScanPlan{
		RepoRoot: repoRoot,
		FileOwnership: map[string]*targetresolve.FileOwnership{
			"package-lock.json": {
				TargetIDs:    []string{"t-a", "t-b"},
				ComponentIDs: []string{"c-a", "c-b"},
				Relation:     targetresolve.RelationWorkspaceRoot,
				Context:      "production",
			},
		},
	}
	owned := &proto.Finding{Tool: "osv", RuleId: "CVE-1", File: filepath.Join(repoRoot, "package-lock.json")}
	unregistered := &proto.Finding{Tool: "osv", RuleId: "CVE-2", File: filepath.Join(repoRoot, "unrelated-file.json")}

	af := attribute(plan, owned, "workspace-root-fallback", "exec-1")
	if af.Finding != owned || af.ScanUnitID != "workspace-root-fallback" || af.ExecutionID != "exec-1" {
		t.Errorf("attribute did not carry the finding, scan unit and execution through: %+v", af)
	}
	if af.Relation != string(targetresolve.RelationWorkspaceRoot) {
		t.Errorf("Relation = %q, want %q", af.Relation, targetresolve.RelationWorkspaceRoot)
	}
	if len(af.TargetIDs) != 2 || af.TargetIDs[0] != "t-a" || af.TargetIDs[1] != "t-b" {
		t.Errorf("TargetIDs = %v, want both t-a and t-b", af.TargetIDs)
	}

	unowned := attribute(plan, unregistered, "workspace-root-fallback", "")
	if len(unowned.TargetIDs) != 0 {
		t.Errorf("a file with no ownership record was credited to %v", unowned.TargetIDs)
	}
	if !ownedByATarget(af) || ownedByATarget(unowned) {
		t.Error("ownedByATarget must keep the fallback lockfile's finding and drop the unowned one")
	}
}
