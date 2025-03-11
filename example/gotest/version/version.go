package version

import (
	"fmt"
	"os"
)

var version string

//ShowVersion
func ShowVersion(module string) {
	if version != "" {
		fmt.Printf("the module of %s %s\n", module, version)
	} else {
		fmt.Printf("the module of %s %s\n", module, os.Getenv("RELEASE_DESC"))
	}
	os.Exit(0)
}

//GetVersion GetVersion
func GetVersion() string {
	return version
}
