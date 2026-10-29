//go:build windows

package main

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

func readParentPassword(prompt string) (string, error) {
	input, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE)
	if err != nil {
		return "", fmt.Errorf("get console input: %w", err)
	}
	var originalMode uint32
	if err := windows.GetConsoleMode(input, &originalMode); err != nil {
		return "", errors.New("parent password setup requires an interactive console")
	}
	if err := windows.SetConsoleMode(input, originalMode&^0x0004); err != nil {
		return "", fmt.Errorf("disable console password echo: %w", err)
	}
	defer windows.SetConsoleMode(input, originalMode)

	fmt.Print(prompt)
	buffer := make([]uint16, 2048)
	var read uint32
	if err := windows.ReadConsole(input, &buffer[0], uint32(len(buffer)), &read, nil); err != nil {
		fmt.Println()
		return "", fmt.Errorf("read parent password: %w", err)
	}
	fmt.Println()
	password := strings.TrimRight(string(windows.UTF16ToString(buffer[:read])), "\r\n")
	if len(password) < 12 {
		return "", errors.New("parent password must be at least 12 characters")
	}
	return password, nil
}
