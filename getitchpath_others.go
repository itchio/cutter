//+build !darwin

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func getItchPath() string {
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("APPDATA")
		return filepath.Join(appData, "itch")
	case "linux":
		configPath := os.Getenv("XDG_CONFIG_HOME")
		if configPath != "" {
			return filepath.Join(configPath, "itch")
		} else {
			homePath := os.Getenv("HOME")
			return filepath.Join(homePath, ".config", "itch")
		}
	}

	panic(fmt.Sprintf("unknown OS: %s", runtime.GOOS))
}
