//+build darwin

package main

import (
	"path/filepath"

	"github.com/itchio/ox/macox"
)

func getItchPath() string {
	appSupport, err := macox.GetApplicationSupportPath()
	if err != nil {
		panic(err)
	}
	return filepath.Join(appSupport, "itch")
}
