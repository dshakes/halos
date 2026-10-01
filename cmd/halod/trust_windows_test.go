//go:build windows

package main

import "golang.org/x/sys/windows"

// Temp dirs live under the runner user's profile, which that user (not SYSTEM or
// Administrators) controls; trust it for tests, as TestMain does with trustedUID.
func init() {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		panic(err)
	}
	testTrustedSID = u.User.Sid.String()
}
