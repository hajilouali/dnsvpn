// Package configlink encodes a client configuration into a single self-contained link
// and back. The server's admin panel hands an operator a `dnsvpn://` link per user; the
// operator sends it over any channel, and a client imports it with no network round trip
// (important, since the server is unreachable during a shutdown). The link carries the
// zone, PSK, user token and optional resolver candidates — everything a client needs.
package configlink

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// Scheme is the URL scheme Android registers an intent filter for.
const Scheme = "dnsvpn://"

// Config is the subset of client settings a link carries.
type Config struct {
	Name       string `json:"name,omitempty"`
	Zone       string `json:"zone"`
	PSK        string `json:"psk"`
	Token      string `json:"token,omitempty"`
	Candidates string `json:"candidates,omitempty"`
}

// Encode renders c as a dnsvpn:// link (base64url of the JSON, no padding).
func Encode(c Config) string {
	b, _ := json.Marshal(c)
	return Scheme + base64.RawURLEncoding.EncodeToString(b)
}

// Decode parses a dnsvpn:// link produced by Encode. It tolerates a trailing slash and
// both padded and unpadded base64url.
func Decode(link string) (Config, error) {
	var c Config
	s := strings.TrimSpace(link)
	if !strings.HasPrefix(s, Scheme) {
		return c, errors.New("configlink: not a dnsvpn:// link")
	}
	s = strings.TrimPrefix(s, Scheme)
	s = strings.Trim(s, "/")
	b, err := decodeB64(s)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if c.Zone == "" || c.PSK == "" {
		return c, errors.New("configlink: link missing zone or psk")
	}
	return c, nil
}

func decodeB64(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}
