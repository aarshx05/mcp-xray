package yararules

import "testing"

func TestGetUnsafeSystemPatternsLoadsEmbeddedRules(t *testing.T) {
	if len(GetUnsafeSystemPatterns()) == 0 {
		t.Fatal("no patterns parsed from the embedded unsafe_patterns.yar")
	}
}
