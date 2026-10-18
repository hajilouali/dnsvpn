//go:build !windows

package scanner

import (
	"bufio"
	"os"
	"strings"
)

// SystemResolvers returns the OS-configured resolvers from /etc/resolv.conf (Linux,
// Android, macOS). During a shutdown the ISP's own resolver is often the one still
// answering, so these belong at the front of the candidate list.
func SystemResolvers() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			ns := fields[1]
			// skip loopback stub resolvers (systemd-resolved) — they can't recurse
			// to us during a shutdown the way the ISP's own resolver can.
			if strings.HasPrefix(ns, "127.") || ns == "::1" {
				continue
			}
			out = append(out, ns)
		}
	}
	return out
}
