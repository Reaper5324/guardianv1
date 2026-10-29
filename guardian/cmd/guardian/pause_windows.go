//go:build windows

package main

import (
	"bufio"
	"os"
)

func waitForDefaultLaunchError() {
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}
