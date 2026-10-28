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

// ldapDial connects and binds as the read-only service account.
func ldapDial(c LDAPConfig) (*ldap.Conn, error) {
	conn, err := ldap.DialURL(c.URL, ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}), ldap.DialWithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.TLSServerName}))
	if err != nil {
		return nil, fmt.Errorf("LDAP unreachable: %w", err)
	}
	conn.SetTimeout(8 * time.Second)
	if err := conn.Bind(fmt.Sprintf("uid=%s,ou=people,%s", ldap.EscapeDN(c.BindUser), c.BaseDN), c.BindPwd); err != nil {
		conn.Close()
		return nil, fmt.Errorf("LDAP service bind failed: %w", err)
	}
	return conn, nil
}

// ldapFind looks a person up by uid or email address; exactly one must match.
func ldapFind(conn *ldap.Conn, c LDAPConfig, login string) (*ldap.Entry, error) {
	esc := ldap.EscapeFilter(login)
	res, err := conn.Search(ldap.NewSearchRequest("ou=people,"+c.BaseDN, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 2, 8, false,
		fmt.Sprintf("(&(objectClass=person)(|(uid=%s)(mail=%s)))", esc, esc),
		[]string{"uid", "mail", "displayName", "memberOf"}, nil))
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}
	if len(res.Entries) != 1 {
		return nil, errBadCredentials
	}
	return res.Entries[0], nil
}

// authenticateLDAP accepts a uid or an email address.
func authenticateLDAP(c LDAPConfig, login, password string) (*ldapUser, error) {
	if password == "" {
		return nil, errBadCredentials
	}
	conn, err := ldapDial(c)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	e, err := ldapFind(conn, c, login)
	if err != nil {
		return nil, err
	}
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

// changeLDAPPassword binds as the user and changes their own password with the LDAP
// Password Modify operation (RFC 3062), which LLDAP, OpenLDAP and others support.
func changeLDAPPassword(c LDAPConfig, uid, current, next string) error {
	conn, err := ldapDial(c)
	if err != nil {
		return err
	}
	defer conn.Close()
	e, err := ldapFind(conn, c, uid)
	if err != nil {
		return err
	}
	if err := conn.Bind(e.DN, current); err != nil {
		return errBadCredentials
	}
	if _, err := conn.PasswordModify(ldap.NewPasswordModifyRequest(e.DN, current, next)); err != nil {
		return fmt.Errorf("the directory refused the new password: %w", err)
	}
	return nil
}
