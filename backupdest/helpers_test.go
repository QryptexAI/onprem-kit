package backupdest

import (
	"os"
	"path/filepath"
)

func writeDotFile(dir, name string) error {
	return os.WriteFile(filepath.Join(dir, name), []byte("partial"), 0o600)
}
