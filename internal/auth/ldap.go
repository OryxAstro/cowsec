package auth

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

// LDAPConfig points at an LDAP directory (OpenLDAP, LLDAP, Active Directory...). The
// service account is only used to look users up; the password check is a bind as the user.
type LDAPConfig struct {
	URL      string // ldaps://host:6360 (or ldap://host:3890, unencrypted)
	BaseDN   string // e.g. dc=example,dc=com
	BindUser string // uid of the read-only service account
	BindPwd  string
	Group    string // only members of this group may log in
	// TLSServerName is the certificate name to verify when URL uses an IP
	// address (e.g. ldaps://10.0.0.5:636 serving a certificate for ldap.example.com).
	TLSServerName string
}

func (c LDAPConfig) Enabled() bool { return c.URL != "" && c.BaseDN != "" }

type ldapUser struct {
	UID         string
	Email       string
	DisplayName string
}

var errBadCredentials = errors.New("invalid username or password")
var errNotInGroup = errors.New("user is not a member of the CowSec group")

// authenticateLDAP accepts a uid or an email address.
func authenticateLDAP(c LDAPConfig, login, password string) (*ldapUser, error) {
	if password == "" {
		return nil, errBadCredentials
	}
	conn, err := ldap.DialURL(c.URL, ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}), ldap.DialWithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.TLSServerName}))
	if err != nil {
		return nil, fmt.Errorf("LDAP unreachable: %w", err)
	}
	defer conn.Close()
	conn.SetTimeout(8 * time.Second)

	people := "ou=people," + c.BaseDN
	if err := conn.Bind(fmt.Sprintf("uid=%s,%s", ldap.EscapeDN(c.BindUser), people), c.BindPwd); err != nil {
		return nil, fmt.Errorf("LDAP service bind failed: %w", err)
	}
	esc := ldap.EscapeFilter(login)
	res, err := conn.Search(ldap.NewSearchRequest(people, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 2, 8, false,
		fmt.Sprintf("(&(objectClass=person)(|(uid=%s)(mail=%s)))", esc, esc),
		[]string{"uid", "mail", "displayName", "memberOf"}, nil))
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}
	if len(res.Entries) != 1 {
		return nil, errBadCredentials
	}
	e := res.Entries[0]
	if err := conn.Bind(e.DN, password); err != nil {
		return nil, errBadCredentials
	}
	groupDN := strings.ToLower(fmt.Sprintf("cn=%s,ou=groups,%s", c.Group, c.BaseDN))
	member := false
	for _, g := range e.GetAttributeValues("memberOf") {
		if strings.ToLower(g) == groupDN {
			member = true
		}
	}
	if !member {
		return nil, errNotInGroup
	}
	return &ldapUser{UID: e.GetAttributeValue("uid"), Email: e.GetAttributeValue("mail"), DisplayName: e.GetAttributeValue("displayName")}, nil
}
