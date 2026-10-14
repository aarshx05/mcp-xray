package reposcan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"mcpxray/proto"

	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

type SecretsScanner struct {
	repoPath string
	config   *Config
}

func NewSecretsScanner(repoPath string, config *Config) *SecretsScanner {
	return &SecretsScanner{
		repoPath: repoPath,
		config:   config,
	}
}

func (s *SecretsScanner) Scan(ctx context.Context) ([]*proto.Finding, error) {
	// 1) Load default config (same rules as CLI when no custom config is provided)
	// NewDetectorDefaultConfig creates a detector with the default ruleset.
	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create detector: %w", err)
	}

	var allFindings []report.Finding

	err = filepath.Walk(s.repoPath, func(filePath string, info os.FileInfo, err error) error {
		// As in SASTScanner.Scan: an entry that cannot be walked is skipped
		// with a warning, but an unreadable scan root fails the scan.
		if err != nil {
			if filePath == s.repoPath {
				return err
			}
			fmt.Fprintf(os.Stderr, "reposcan: skipping %s: %v\n", filePath, err)
			return nil
		}

		// Check if path should be excluded based on config
		if s.config.ShouldExclude(filePath) {
			// Skip entire directory if it matches exclude pattern
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if info.IsDir() {
			return nil
		}

		// Skip non-regular files: a symlink (to a directory, or to itself)
		// cannot be read as a file, and a FIFO would block. A symlinked
		// file inside the repository is scanned at its real path.
		if !info.Mode().IsRegular() {
			return nil
		}

		// Skip files larger than configured max size
		if info.Size() > s.config.MaxFileSize {
			return nil
		}

		// Read file content
		fileContent, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reposcan: skipping unreadable %s: %v\n", filePath, err)
			return nil
		}

		// Detect unsafe commands in this file
		findings := detector.DetectString(string(fileContent))
		for _, finding := range findings {
			finding.File = filePath
			allFindings = append(allFindings, finding)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk repository: %w", err)
	}

	fmt.Printf("Found %d secrets\n", len(allFindings))
	return FromGitleaks(allFindings), nil
}

func FromGitleaks(findings []report.Finding) []*proto.Finding {
	out := make([]*proto.Finding, 0, len(findings))

	for _, f := range findings {
		out = append(out, &proto.Finding{
			Tool:     "gitleaks",
			Type:     proto.FindingType_FINDING_TYPE_SECRETS,
			Severity: proto.RiskSeverity_RISK_SEVERITY_HIGH, // treat all secrets as high/error
			RuleId:   f.RuleID,
			Title:    f.Description,
			File:     f.File,
			Line:     int32(f.StartLine),
			Message:  f.Description, // avoid empty message
		})
	}

	return out
}
