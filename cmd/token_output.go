package cmd

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeTokenFile writes token to outputPath atomically using a private temp
// file in the destination directory. Concurrent commands therefore cannot
// share a temporary file or observe a partially written token. Replacing the
// final path remains last-writer-wins because that path explicitly identifies
// one output.
func writeTokenFile(outputPath string, token []byte) error {
	// Preserve --output=/dev/stdout, /dev/stderr, and other non-regular
	// destinations. Atomic rename is only meaningful for regular files.
	if info, err := os.Stat(outputPath); err == nil && !info.Mode().IsRegular() {
		return os.WriteFile(outputPath, token, info.Mode().Perm())
	}

	tempFile, err := os.CreateTemp(filepath.Dir(outputPath), ".gotpm-token-*")
	if err != nil {
		return fmt.Errorf("creating temporary token file: %w", err)
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath) // No-op after a successful rename.

	if _, err := tempFile.Write(token); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("writing temporary token file: %w", err)
	}
	if err := tempFile.Chmod(0o644); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("setting token file permissions: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("closing temporary token file: %w", err)
	}
	if err := os.Rename(tempPath, outputPath); err != nil {
		return fmt.Errorf("replacing token output file: %w", err)
	}
	return nil
}
