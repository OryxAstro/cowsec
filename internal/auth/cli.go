package auth

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

const cliUsage = `CowSec account administration

  cowsec auth local-admin set <name>     create/replace a local account (prompts for password)
  cowsec auth local-admin remove <name>  delete a local admin
  cowsec auth totp reset <user>          remove a user's authenticator (re-enrols at next login) and end their sessions
  cowsec auth status                     show local admins, enrolled users and session count
`

func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

// RunCLI handles `cowsec auth ...`; it edits the same state file the
// running server reads (the server reloads it when it changes).
func RunCLI(args []string, statePath string) int {
	st, err := OpenStore(statePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	switch {
	case len(args) == 3 && args[0] == "local-admin" && args[1] == "set":
		name := strings.TrimSpace(args[2])
		pw, err := readPassword("New password (min 12 characters): ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		if len(pw) < 12 {
			fmt.Fprintln(os.Stderr, "error: password must be at least 12 characters")
			return 1
		}
		if term.IsTerminal(int(os.Stdin.Fd())) {
			again, _ := readPassword("Repeat password: ")
			if again != pw {
				fmt.Fprintln(os.Stderr, "error: passwords do not match")
				return 1
			}
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		if err := st.SetLocalAdmin(name, string(hash)); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		_, enrolled := st.TOTP(name)
		fmt.Printf("Local admin %q saved to %s.\n", name, statePath)
		if !enrolled {
			fmt.Println("Sign in to CowSec with it to enrol an authenticator app (required).")
		}
	case len(args) == 3 && args[0] == "local-admin" && args[1] == "remove":
		if err := st.DeleteLocalAdmin(args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Printf("Local admin %q removed.\n", args[2])
	case len(args) == 3 && args[0] == "totp" && args[1] == "reset":
		_ = st.DeleteTOTP(args[2])
		n := st.deleteUserSessions(args[2])
		fmt.Printf("Authenticator for %q removed; %d session(s) ended. They will re-enrol at next sign-in.\n", args[2], n)
	case len(args) == 1 && args[0] == "status":
		admins := st.LocalAdminNames()
		sort.Strings(admins)
		st.mu.Lock()
		enrolled := []string{}
		for u := range st.st.TOTP {
			enrolled = append(enrolled, u)
		}
		sessions := len(st.st.Sessions)
		st.mu.Unlock()
		sort.Strings(enrolled)
		fmt.Printf("State file:        %s\nLocal admins:      %s\nTOTP enrolled:     %s\nActive sessions:   %d\n",
			statePath, strings.Join(admins, ", "), strings.Join(enrolled, ", "), sessions)
	default:
		fmt.Print(cliUsage)
		return 2
	}
	return 0
}
