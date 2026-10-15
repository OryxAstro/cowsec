package mailcow

import (
	"fmt"
	"strconv"
	"strings"
)

// Request bodies for domains, mailboxes and aliases. Every field is optional so the same
// type serves "add" (with defaults filled by mailcow) and "edit" (only what changed).

type domainIn struct {
	Domain             *string   `json:"domain"`
	Description        *string   `json:"description"`
	Active             *bool     `json:"active"`
	Mailboxes          *int      `json:"mailboxes"`
	Aliases            *int      `json:"aliases"`
	DefQuota           *int      `json:"defquota"`
	MaxQuota           *int      `json:"maxquota"`
	Quota              *int      `json:"quota"`
	BackupMX           *bool     `json:"backupmx"`
	RelayAllRecipients *bool     `json:"relay_all_recipients"`
	RelayUnknownOnly   *bool     `json:"relay_unknown_only"`
	GAL                *bool     `json:"gal"`
	Tags               *[]string `json:"tags"`
	RLValue            *int      `json:"rl_value"` // only when adding; later changes go through /ratelimits
	RLFrame            *string   `json:"rl_frame"`
}

func (in domainIn) attrs() (map[string]interface{}, error) {
	a := map[string]interface{}{}
	if in.Description != nil {
		a["description"] = trim(*in.Description, 255)
	}
	for k, v := range map[string]*bool{"active": in.Active, "backupmx": in.BackupMX, "relay_all_recipients": in.RelayAllRecipients,
		"relay_unknown_only": in.RelayUnknownOnly, "gal": in.GAL} {
		if v != nil {
			a[k] = flag(*v)
		}
	}
	for _, f := range []struct {
		n   string
		v   *int
		max int
		k   string
	}{{"mailboxes", in.Mailboxes, 100000, "mailboxes"}, {"aliases", in.Aliases, 100000, "aliases"},
		{"default mailbox quota", in.DefQuota, 10485760, "defquota"}, {"maximum mailbox quota", in.MaxQuota, 10485760, "maxquota"},
		{"domain quota", in.Quota, 104857600, "quota"}} {
		if err := num(f.n, f.v, f.max, a, f.k); err != nil {
			return nil, err
		}
	}
	if in.Tags != nil {
		t, err := tags(*in.Tags)
		if err != nil {
			return nil, err
		}
		a["tags"] = t
	}
	if in.RLValue != nil && *in.RLValue > 0 {
		if *in.RLValue > 1000000 || in.RLFrame == nil || !rlFrames[*in.RLFrame] {
			return nil, fmt.Errorf("a rate limit is a number of messages per s, m, h or d")
		}
		a["rl_value"], a["rl_frame"] = strconv.Itoa(*in.RLValue), *in.RLFrame
	}
	return a, nil
}

type mailboxIn struct {
	LocalPart              *string   `json:"local_part"`
	Domain                 *string   `json:"domain"`
	Name                   *string   `json:"name"`
	Password               *string   `json:"password"`
	Quota                  *int      `json:"quota"`
	Active                 *bool     `json:"active"`
	ForcePwUpdate          *bool     `json:"force_pw_update"`
	ForceTFA               *bool     `json:"force_tfa"`
	SenderACL              *[]string `json:"sender_acl"` // addresses, @domains, "*" (any) or [] (only its own addresses)
	TLSEnforceIn           *bool     `json:"tls_enforce_in"`
	TLSEnforceOut          *bool     `json:"tls_enforce_out"`
	Protocols              *[]string `json:"protocols"` // imap pop3 smtp sieve eas dav
	SOGo                   *bool     `json:"sogo_access"`
	Tags                   *[]string `json:"tags"`
	TaggedMailHandler      *string   `json:"tagged_mail_handler"`
	QuarantineNotification *string   `json:"quarantine_notification"`
	QuarantineCategory     *string   `json:"quarantine_category"`
	RelayHost              *int      `json:"relayhost"`
}

var (
	protocols    = map[string]bool{"imap": true, "pop3": true, "smtp": true, "sieve": true, "eas": true, "dav": true}
	taggedModes  = map[string]bool{"subfolder": true, "subject": true, "none": true}
	notifyModes  = map[string]bool{"never": true, "hourly": true, "daily": true, "weekly": true}
	categoryKind = map[string]bool{"reject": true, "add_header": true, "all": true}
)

func (in mailboxIn) attrs() (map[string]interface{}, error) {
	a := map[string]interface{}{}
	if in.Name != nil {
		a["name"] = trim(*in.Name, 255)
	}
	if in.Password != nil {
		if len(*in.Password) < 10 || len(*in.Password) > 256 {
			return nil, fmt.Errorf("password must be 10-256 characters")
		}
		a["password"], a["password2"] = *in.Password, *in.Password
	}
	if err := num("quota", in.Quota, 10485760, a, "quota"); err != nil {
		return nil, err
	}
	for k, v := range map[string]*bool{"active": in.Active, "force_pw_update": in.ForcePwUpdate, "force_tfa": in.ForceTFA,
		"tls_enforce_in": in.TLSEnforceIn, "tls_enforce_out": in.TLSEnforceOut, "sogo_access": in.SOGo} {
		if v != nil {
			a[k] = flag(*v)
		}
	}
	if in.Protocols != nil {
		on := map[string]bool{}
		for _, p := range *in.Protocols {
			if !protocols[p] {
				return nil, fmt.Errorf("unknown protocol %q", p)
			}
			on[p] = true
		}
		list := []string{}
		for p := range protocols {
			a[p+"_access"] = flag(on[p])
			if on[p] {
				list = append(list, p)
			}
		}
		a["protocol_access"] = list
	}
	if in.Tags != nil {
		t, err := tags(*in.Tags)
		if err != nil {
			return nil, err
		}
		a["tags"] = t
	}
	if in.SenderACL != nil {
		acl := []string{}
		for _, e := range *in.SenderACL {
			e = strings.ToLower(strings.TrimSpace(e))
			switch {
			case e == "":
				continue
			case e == "*", reEmail.MatchString(e), strings.HasPrefix(e, "@") && reDomain.MatchString(e[1:]):
				acl = append(acl, e)
			default:
				return nil, fmt.Errorf("%q: enter an address, @domain or * for any sender", e)
			}
		}
		if len(acl) > 200 {
			return nil, fmt.Errorf("at most 200 sender entries")
		}
		if len(acl) == 0 {
			acl = []string{"default"} // mailcow's way of clearing the list
		}
		a["sender_acl"] = acl
	}
	if in.TaggedMailHandler != nil {
		if !taggedModes[*in.TaggedMailHandler] {
			return nil, fmt.Errorf("tagged mail: subfolder, subject or none")
		}
		a["tagged_mail_handler"] = *in.TaggedMailHandler
	}
	if in.QuarantineNotification != nil {
		if !notifyModes[*in.QuarantineNotification] {
			return nil, fmt.Errorf("quarantine notifications: never, hourly, daily or weekly")
		}
		a["quarantine_notification"] = *in.QuarantineNotification
	}
	if in.QuarantineCategory != nil {
		if !categoryKind[*in.QuarantineCategory] {
			return nil, fmt.Errorf("quarantine category: reject, add_header or all")
		}
		a["quarantine_category"] = *in.QuarantineCategory
	}
	if in.RelayHost != nil {
		if *in.RelayHost < 0 {
			return nil, fmt.Errorf("invalid relay host")
		}
		a["relayhost"] = strconv.Itoa(*in.RelayHost)
	}
	return a, nil
}

type aliasIn struct {
	Address        *string `json:"address"`
	Goto           *string `json:"goto"`
	GotoMode       *string `json:"goto_mode"` // addresses | discard | spam | ham
	Active         *bool   `json:"active"`
	SOGoVisible    *bool   `json:"sogo_visible"`
	Internal       *bool   `json:"internal"`
	PrivateComment *string `json:"private_comment"`
	PublicComment  *string `json:"public_comment"`
}

func (in aliasIn) attrs() (map[string]interface{}, error) {
	a := map[string]interface{}{}
	mode := "addresses"
	if in.GotoMode != nil {
		mode = *in.GotoMode
	}
	switch mode {
	case "discard":
		a["goto_null"] = "1"
	case "spam":
		a["goto_spam"] = "1"
	case "ham":
		a["goto_ham"] = "1"
	case "addresses":
		if in.Goto != nil {
			t, err := gotoList(*in.Goto)
			if err != nil {
				return nil, err
			}
			a["goto"] = t
		}
	default:
		return nil, fmt.Errorf("invalid delivery mode")
	}
	for k, v := range map[string]*bool{"active": in.Active, "sogo_visible": in.SOGoVisible, "internal": in.Internal} {
		if v != nil {
			a[k] = flag(*v)
		}
	}
	if in.PrivateComment != nil {
		a["private_comment"] = trim(*in.PrivateComment, 160)
	}
	if in.PublicComment != nil {
		a["public_comment"] = trim(*in.PublicComment, 160)
	}
	return a, nil
}

func tags(list []string) ([]string, error) {
	out := []string{}
	for _, t := range list {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if len(t) > 64 || strings.ContainsAny(t, "<>\"'`\n") {
			return nil, fmt.Errorf("invalid tag %q", t)
		}
		out = append(out, t)
	}
	if len(out) > 50 {
		return nil, fmt.Errorf("at most 50 tags")
	}
	return out, nil
}
