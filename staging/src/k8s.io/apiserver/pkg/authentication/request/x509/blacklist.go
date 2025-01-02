package x509

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"sigs.k8s.io/yaml"
)

type Blacklist struct {
	users map[string]userBlacklist
}

type userBlacklist struct {
	ips map[string]struct{}
}

func ParseBlacklist(path string) (*Blacklist, error) {
	rawData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var data map[string][]string
	err = yaml.Unmarshal(rawData, &data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal blacklist data: %w", err)
	}

	bl := &Blacklist{
		users: make(map[string]userBlacklist, len(data)),
	}
	for user, ipList := range data {
		ubl := userBlacklist{
			ips: make(map[string]struct{}, len(ipList)),
		}
		for _, ip := range ipList {
			ubl.ips[ip] = struct{}{}
		}
		bl.users[user] = ubl
	}

	return bl, nil
}

func (b *Blacklist) isBlock(user *authenticator.Response, req *http.Request) bool {
	if b == nil {
		return false
	}
	if b.users == nil {
		return false
	}

	userBlacklist, ok := b.users[user.User.GetName()]
	if !ok {
		return false
	}

	if userBlacklist.ips == nil {
		return false
	}

	host := req.Host
	if strings.Contains(host, ":") {
		host, _, _ = net.SplitHostPort(host)
	}
	if host == "" {
		return false
	}

	_, block := userBlacklist.ips[host]
	return block
}
