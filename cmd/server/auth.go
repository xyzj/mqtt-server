package server

import (
	"fmt"
	"os"

	"github.com/xyzj/mqtt-server/hooks/auth"
	"github.com/xyzj/toolbox/config"
	"gopkg.in/yaml.v3"
)

var authSample = []byte(`thisisanACLsample:
    password: lostjudgment
    acl:
        deny/#: 0
        read/#: 1
        write/#: 2
        rw/#: 3
    disallow: true
control:
    password: daysgone
    acl:
        down/#: 3
        up/#: 3
user01:
    password: concord
    acl:
        down/+/user01/#: 1
        up/+/user01/#: 2
`)

type users map[string]userRule

// UserRule defines a set of access rules for a specific user.
type userRule struct {
	Username string         `json:"username,omitempty" yaml:"username,omitempty"` // the username of a user
	Password config.VString `json:"password,omitempty" yaml:"password,omitempty"` // the password of a user
	ACL      auth.Filters   `json:"acl,omitempty" yaml:"acl,omitempty"`           // filters to match, if desired
	Disallow bool           `json:"disallow,omitempty" yaml:"disallow,omitempty"` // allow or disallow the user
}

func FromAuthfile(authfile string, codedpwd bool) (*auth.Ledger, error) {
	if authfile == "" {
		return nil, fmt.Errorf("filename is empty")
	}
	b, err := os.ReadFile(authfile)
	if err != nil {
		return nil, err
	}
	au := users{}
	err = yaml.Unmarshal(b, &au)
	if err != nil {
		return nil, err
	}
	ac := auth.Users{}
	pwd := ""
	for username, rule := range au {
		if rule.Disallow {
			continue
		}
		if codedpwd {
			pwd = rule.Password.TryDecode()
		} else {
			pwd = rule.Password.String()
		}
		ac[username] = auth.UserRule{
			Username: auth.RString(rule.Username),
			Password: auth.RString(pwd),
			ACL:      rule.ACL,
			Disallow: rule.Disallow,
		}
	}
	return &auth.Ledger{Users: ac, Auth: auth.AuthRules{}, ACL: auth.ACLRules{}}, nil
}

func InitAuthfile(filename string) error {
	return os.WriteFile(filename, authSample, 0o664)
}
