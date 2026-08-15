package scheduler

import "runtime"

// testShellEcho returns the binary and flags to echo a string,
// compatible with both Windows (cmd /c echo) and Unix (sh -c echo).
func testShellEcho(text string) (binary string, flags []string) {
	if runtime.GOOS == "windows" {
		return "cmd", []string{"/c", "echo", text}
	}
	return "sh", []string{"-c", "echo " + text}
}

// testShellFail returns the binary and flags to echo something and exit 1,
// compatible with both Windows and Unix.
func testShellFail(text string) (binary string, flags []string) {
	if runtime.GOOS == "windows" {
		return "cmd", []string{"/c", "echo " + text + " && exit 1"}
	}
	return "sh", []string{"-c", "echo " + text + " && exit 1"}
}
