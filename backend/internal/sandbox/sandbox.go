package sandbox

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/landlock-lsm/go-landlock/landlock"
)

// ExecuteSandboxed confines running threads to a strictly designated path
func ExecuteSandboxed(targetFunc func()) error {
	// Guard against unsupported target architectures gracefully
	if runtime.GOOS!= "linux" {
		// If running locally on Mac/Windows, log warning and bypass so debugging works
		fmt.Printf(" Host OS is %s. Landlock execution skipped (BestEffort Fallback)\n", runtime.GOOS)
		targetFunc()
		return nil
	}

	// Establish Sandbox: Restricted strictly to reading program folders and reading/writing temporary files
	err := landlock.V3.BestEffort().RestrictPaths(
		landlock.RODirs("/usr", "/bin", "/lib", "/lib64"),
		landlock.RWDirs("/tmp"),
	)
	if err!= nil {
		return errors.New("failed to lock file descriptors: " + err.Error())
	}

	// Safely execute targeted logic inside sandboxed environment
	targetFunc()
	return nil
}