// Command fakedocker stands in for the docker CLI in eval tests, so they run on
// Windows too (a #!/bin/sh stub cannot be exec'd there). Behaviour comes from env:
//
//	FAKE_DOCKER_LOG          append each call's arguments, space-joined, as one line
//	FAKE_DOCKER_PROBE_EXIT   a `sandbox linux` call prints Landlock's failure and exits with this code
//	FAKE_DOCKER_STDERR_FILE  every call replays this file to stderr and exits FAKE_DOCKER_EXIT (default 101)
//
// Otherwise it succeeds, creating the destination of `docker cp <c:path> <dir>`.
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	args := os.Args[1:]
	line := strings.Join(args, " ")
	if p := os.Getenv("FAKE_DOCKER_LOG"); p != "" {
		if f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			fmt.Fprintln(f, line)
			_ = f.Close()
		}
	}
	if p := os.Getenv("FAKE_DOCKER_STDERR_FILE"); p != "" {
		b, _ := os.ReadFile(p)
		_, _ = os.Stderr.Write(b)
		code := 101
		if n, err := strconv.Atoi(os.Getenv("FAKE_DOCKER_EXIT")); err == nil {
			code = n
		}
		os.Exit(code)
	}
	if x := os.Getenv("FAKE_DOCKER_PROBE_EXIT"); x != "" && strings.Contains(line, " sandbox linux ") {
		fmt.Fprintln(os.Stderr, "error applying legacy Linux sandbox restrictions: Sandbox(LandlockRestrict)")
		n, _ := strconv.Atoi(x)
		os.Exit(n)
	}
	if len(args) >= 3 && strings.Contains(args[1], ":") { // docker cp out creates its destination
		_ = os.MkdirAll(args[2], 0o755)
	}
}
