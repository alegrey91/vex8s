//go:build integration
// +build integration

package integration

import (
	"embed"
	"os"
	"path/filepath"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

//go:embed examples/*
var examples embed.FS

func TestVex8s(t *testing.T) {
	testscript.Run(t, testscript.Params{
		TestWork:            true,
		Dir:                 "testdata",
		RequireExplicitExec: true,
		Setup: func(env *testscript.Env) error {
			err := extractFiles(env)
			return err
		},
	})
}

// extractFiles extract embedded files to test working directory
func extractFiles(env *testscript.Env) error {
	entries, err := examples.ReadDir("examples")
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		data, err := examples.ReadFile(filepath.Join("examples", entry.Name()))
		if err != nil {
			return err
		}

		dst := filepath.Join(env.WorkDir, entry.Name())
		if err := os.WriteFile(dst, data, 0644); err != nil {
			return err
		}
	}
	return nil
}
