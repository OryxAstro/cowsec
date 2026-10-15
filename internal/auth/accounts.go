package auth

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var accountName = regexp.MustCompile(`^[a-zA-Z0-9._@-]{2,64}$`)

// CreateLocalAccount adds (or replaces) a local account. The user enrols an
// authenticator app at their first sign-in.
func CreateLocalAccount(statePath, name, password string) error {
	name = strings.TrimSpace(name)
	if !accountName.MatchString(name) {
		return fmt.Errorf("username: 2-64 letters, digits, . _ @ or -")
	}
	if len(password) < 12 {
		return fmt.Errorf("password must be at least 12 characters")
	}
	st, err := OpenStore(statePath)
	if err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return err
	}
	return st.SetLocalAdmin(name, string(hash))
}

// LocalAccounts lists the local account names.
func LocalAccounts(statePath string) []string {
	st, err := OpenStore(statePath)
	if err != nil {
		return nil
	}
	return st.LocalAdminNames()
}
