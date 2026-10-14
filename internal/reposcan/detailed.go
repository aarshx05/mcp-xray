package reposcan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"mcpxray/proto"
)

// ScannerStatus is the outcome of one scanner execution.
type ScannerStatus string

const (
	ScannerSuccess     ScannerStatus = "success"
	ScannerFailed      ScannerStatus = "failed"
	ScannerSkipped     ScannerStatus = "skipped"
	ScannerUnsupported ScannerStatus = "unsupported"
)

// ScannerExecution records one scanner run over one scan unit. A failed run
// is never reported as zero findings.
type ScannerExecution struct {
	ID           string        `json:"id"`
	ScanUnitID   string        `json:"scanUnitId"`
	Scanner      string        `json:"scanner"`
	Status       ScannerStatus `json:"status"`
	FindingCount int           `json:"findingCount"`
	InputSummary string        `json:"inputSummary,omitempty"`
	DurationMs   int64         `json:"durationMs,omitempty"`
	Error        string        `json:"error,omitempty"`
}

// ExecutedFinding is a raw scanner finding together with the execution that
// produced it.
type ExecutedFinding struct {
	Finding     *proto.Finding
	ExecutionID string
}

// DetailedScanResult is every finding and execution of one ScanDetailed call.
type DetailedScanResult struct {
	Findings   []ExecutedFinding
	Executions []ScannerExecution
}

// ScannerSelection names the scanners to run.
type ScannerSelection struct{ SCA, Secrets, SAST bool }

func executionID(scanUnitID, scanner string) string {
	sum := sha256.Sum256([]byte(scanUnitID + "\x00" + scanner))
	return "exec-" + hex.EncodeToString(sum[:8])
}

// ScanDetailed runs the selected scanners over one scan unit, recording an
// execution per scanner (skipped ones included) and each finding's
// execution. Successful raw findings are returned unchanged.
func ScanDetailed(ctx context.Context, root string, config *Config, selection ScannerSelection, scanUnitID string, inputSummary string) DetailedScanResult {
	var result DetailedScanResult
	result.run(scanUnitID, "osv", inputSummary, selection.SCA, func() ([]*proto.Finding, error) { return NewSCAScanner(root, config).Scan(ctx) })
	result.run(scanUnitID, "gitleaks", inputSummary, selection.Secrets, func() ([]*proto.Finding, error) { return NewSecretsScanner(root, config).Scan(ctx) })
	result.run(scanUnitID, "sast", inputSummary, selection.SAST, func() ([]*proto.Finding, error) { return NewSASTScanner(root, config).Scan(ctx) })
	return result
}

// ScanRootOwnFilesDetailed is ScanRootOwnFiles recorded as one osv
// execution of scanUnitID.
func ScanRootOwnFilesDetailed(root, scanUnitID, inputSummary string) DetailedScanResult {
	var result DetailedScanResult
	result.run(scanUnitID, "osv", inputSummary, true, func() ([]*proto.Finding, error) { return ScanRootOwnFiles(root) })
	return result
}

// run executes one scanner when enabled and records its execution, and the
// execution of each finding it reports.
func (r *DetailedScanResult) run(scanUnitID, scanner, inputSummary string, enabled bool, scan func() ([]*proto.Finding, error)) {
	execution := ScannerExecution{ID: executionID(scanUnitID, scanner), ScanUnitID: scanUnitID, Scanner: scanner, Status: ScannerSkipped, InputSummary: inputSummary}
	if enabled {
		start := time.Now()
		findings, err := scan()
		execution.DurationMs = time.Since(start).Milliseconds()
		switch {
		case IsUnsupportedScanError(err):
			execution.Status, execution.Error = ScannerUnsupported, err.Error()
		case err != nil:
			execution.Status, execution.Error = ScannerFailed, err.Error()
		default:
			execution.Status, execution.FindingCount = ScannerSuccess, len(findings)
			for _, finding := range findings {
				r.Findings = append(r.Findings, ExecutedFinding{Finding: finding, ExecutionID: execution.ID})
			}
		}
	}
	r.Executions = append(r.Executions, execution)
}
