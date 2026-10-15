package aggregation

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"mcpxray/proto"
)

// AttributedFinding is one raw scanner finding together with the targets,
// components and scan unit it is credited to.
type AttributedFinding struct {
	Finding      *proto.Finding
	TargetIDs    []string
	ComponentIDs []string
	ScanUnitID   string
	ExecutionID  string
	Relation     string
	Context      string
}

// RawInstance records one scanner execution that reported an aggregated
// finding.
type RawInstance struct {
	ScanUnitID  string `json:"scanUnitId"`
	ExecutionID string `json:"executionId"`
	Scanner     string `json:"scanner"`
}

// AggregatedFinding is one unique finding, by Fingerprint, merged from every
// raw report of it across scan units.
type AggregatedFinding struct {
	Finding        *proto.Finding
	Fingerprint    string
	RawCount       int
	DuplicateCount int
	TargetIDs      []string
	ComponentIDs   []string
	ScanUnitIDs    []string
	Relations      []string
	Contexts       []string
	RawInstances   []RawInstance
}

// SARIFProperties is the attribution attached to the finding's SARIF result.
func (a *AggregatedFinding) SARIFProperties() map[string]interface{} {
	properties := map[string]interface{}{
		"fingerprint":    a.Fingerprint,
		"rawCount":       a.RawCount,
		"duplicateCount": a.DuplicateCount,
		"targetIds":      a.TargetIDs,
		"componentIds":   a.ComponentIDs,
		"scanUnitIds":    a.ScanUnitIDs,
		"relations":      a.Relations,
		"context":        a.Contexts,
	}
	if len(a.RawInstances) > 0 {
		properties["rawInstances"] = a.RawInstances
	}
	return properties
}

// Fingerprint identifies a finding independently of which scan unit reported
// it: the same issue at the same repository-relative location hashes the same.
func Fingerprint(repoRoot string, finding *proto.Finding) string {
	if finding == nil {
		return ""
	}
	path := finding.File
	if path != "" {
		if rel, err := filepath.Rel(repoRoot, path); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			path = filepath.ToSlash(rel)
		} else {
			path = filepath.ToSlash(filepath.Clean(path))
		}
	}
	message := strings.TrimSpace(finding.Message)
	if message == "" {
		message = strings.TrimSpace(finding.Title)
	}
	value := strings.Join([]string{finding.Tool, string(finding.Type.String()), finding.RuleId, path, formatInt(finding.Line), finding.Package, finding.Version, message}, "\x00")
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:16])
}

func formatInt(value int32) string {
	if value == 0 {
		return ""
	}
	return strconv.FormatInt(int64(value), 10)
}

// Aggregate merges raw findings that share a Fingerprint, sorted by
// fingerprint so the output is deterministic.
func Aggregate(repoRoot string, inputs []AttributedFinding) []*AggregatedFinding {
	byFingerprint := make(map[string]*AggregatedFinding)
	for _, input := range inputs {
		if input.Finding == nil {
			continue
		}
		fp := Fingerprint(repoRoot, input.Finding)
		agg := byFingerprint[fp]
		if agg == nil {
			agg = &AggregatedFinding{Finding: input.Finding, Fingerprint: fp}
			byFingerprint[fp] = agg
		}
		agg.RawCount++
		agg.TargetIDs = appendUnique(agg.TargetIDs, input.TargetIDs...)
		agg.ComponentIDs = appendUnique(agg.ComponentIDs, input.ComponentIDs...)
		agg.ScanUnitIDs = appendUnique(agg.ScanUnitIDs, input.ScanUnitID)
		agg.Relations = appendUnique(agg.Relations, input.Relation)
		agg.Contexts = appendUnique(agg.Contexts, input.Context)
		agg.RawInstances = append(agg.RawInstances, RawInstance{
			ScanUnitID:  input.ScanUnitID,
			ExecutionID: input.ExecutionID,
			Scanner:     input.Finding.Tool,
		})
	}
	result := make([]*AggregatedFinding, 0, len(byFingerprint))
	for _, value := range byFingerprint {
		value.DuplicateCount = value.RawCount - 1
		sort.Strings(value.TargetIDs)
		sort.Strings(value.ComponentIDs)
		sort.Strings(value.ScanUnitIDs)
		sort.Strings(value.Relations)
		sort.Strings(value.Contexts)
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Fingerprint < result[j].Fingerprint })
	return result
}

func appendUnique(values []string, additions ...string) []string {
	seen := make(map[string]bool, len(values)+len(additions))
	for _, value := range values {
		if value != "" {
			seen[value] = true
		}
	}
	for _, value := range additions {
		if value != "" && !seen[value] {
			seen[value] = true
			values = append(values, value)
		}
	}
	return values
}

// ContextForPath classifies a repository-relative path as production code or
// one of the non-production contexts (test, docs, example, ...). It is the
// single classification used everywhere a finding's context is computed
// (targetresolve's file ownership calls it too).
//
// A document is "docs" wherever it is: a markup file (.md, .rst, ...) or a
// conventional project document (README, LICENSE, SECURITY.txt, ...) with no
// extension or a plain-text one -- security.go and history.ts are source
// code. Otherwise the path's DIRECTORY segments decide, so src/build.go and
// src/tools.go are ordinary production files; when several directories are
// tagged, the outermost one wins: vendor/x/testing/y.go is vendored code,
// not the project's own tests. A directory is tagged only by its
// conventional lower-case name: a capitalized one (Options/Docs/,
// Webapp/Deployment/) is a source namespace, not a docs or deployment tree.
// Only a file in no tagged directory is then checked against the
// languages' test-file naming conventions (foo_test.go, foo.test.ts,
// test_foo.py, ...).
func ContextForPath(repoRelativePath string) string {
	normalized := filepath.ToSlash(filepath.Clean(repoRelativePath))
	base := strings.ToLower(path.Base(normalized))
	ext := path.Ext(base)
	if markupExtensions[ext] || (plainDocumentExtensions[ext] && documentationStems[strings.TrimSuffix(base, ext)]) {
		return "docs"
	}

	if dir := path.Dir(normalized); dir != "." && dir != "/" {
		for _, segment := range strings.Split(strings.Trim(dir, "/"), "/") {
			if label, ok := contextDirectoryToLabel[segment]; ok {
				return label
			}
			if isDotnetTestProject(segment) {
				return "test"
			}
		}
	}
	if isTestFileName(base) {
		return "test"
	}
	return "production"
}

// isDotnetTestProject reports whether a directory is named like a .NET test
// project: Foo.Tests, Foo.UnitTests, Foo.IntegrationTests.
func isDotnetTestProject(segment string) bool {
	for _, suffix := range []string{".Tests", ".UnitTests", ".IntegrationTests"} {
		if strings.HasSuffix(segment, suffix) {
			return true
		}
	}
	return false
}

// isTestFileName reports whether a (lower-cased) file name follows a
// language's test-file convention: Go's foo_test.go, JavaScript's
// foo.test.ts and foo.spec.js, and pytest's test_foo.py, foo_test.py and
// conftest.py.
func isTestFileName(base string) bool {
	switch ext := path.Ext(base); ext {
	case ".go":
		return strings.HasSuffix(base, "_test.go")
	case ".py":
		return base == "conftest.py" || strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py")
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts":
		stem := strings.TrimSuffix(base, ext)
		return strings.HasSuffix(stem, ".test") || strings.HasSuffix(stem, ".spec")
	}
	return false
}

// documentationStems are the conventional names of top-level project
// documents, which are docs with no extension (README, LICENSE, NOTICE, ...)
// or a plain-text one; a markup file is a document whatever its name.
var documentationStems = map[string]bool{
	"readme": true, "changelog": true, "changes": true, "contributing": true, "contributors": true,
	"license": true, "licence": true, "notice": true, "authors": true, "troubleshooting": true,
	"code_of_conduct": true, "code-of-conduct": true, "security": true, "history": true,
}

var plainDocumentExtensions = map[string]bool{"": true, ".txt": true, ".html": true, ".org": true}

var markupExtensions = map[string]bool{
	".md": true, ".markdown": true, ".mdx": true, ".rst": true, ".adoc": true, ".asciidoc": true,
}

// contextDirectoryToLabel maps a directory name to the context of everything
// beneath it.
var contextDirectoryToLabel = map[string]string{
	"generated":        "generated",
	"test":             "test",
	"tests":            "test",
	"__tests__":        "test",
	"testing":          "test",
	"testdata":         "test",
	"e2e":              "test",
	"__mocks__":        "test",
	"mocks":            "test",
	"benchmark":        "test",
	"benchmarks":       "test",
	"evals":            "test",
	"fixture":          "fixture",
	"fixtures":         "fixture",
	"testfixtures":     "fixture",
	"docs":             "docs",
	"documentation":    "docs",
	"doc":              "docs",
	"docs_src":         "docs",
	"examples":         "example",
	"example":          "example",
	"samples":          "example",
	".github":          "ci",
	"ci":               "ci",
	".circleci":        "ci",
	".azure-pipelines": "ci",
	"scripts":          "build",
	"script":           "build",
	"eng":              "build",
	"deploy":           "deployment",
	"deployment":       "deployment",
	"infra":            "deployment",
	"terraform":        "deployment",
	"helm":             "deployment",
	"k8s":              "deployment",
	"build":            "build",
	"vendor":           "vendored",
	"third_party":      "vendored",
	"third-party":      "vendored",
	"external":         "vendored",
}
