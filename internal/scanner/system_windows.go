//go:build windows

package scanner

import (
	"os/exec"
	"strings"
)

// SystemResolvers returns the OS-configured resolvers by asking PowerShell for the
// per-adapter DNS servers. During a shutdown the ISP's own resolver is often the one
// still answering, so these belong at the front of the candidate list. Best-effort:
// on any error it returns nil and the caller falls back to DefaultCandidates.
func SystemResolvers() []string {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-DnsClientServerAddress -AddressFamily IPv4 | "+
			"Select-Object -ExpandProperty ServerAddresses")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var res []string
	for _, line := range strings.Split(string(out), "\n") {
		ip := strings.TrimSpace(line)
		if ip == "" || strings.HasPrefix(ip, "127.") || ip == "::1" {
			continue
		}
		if !seen[ip] {
			seen[ip] = true
			res = append(res, ip)
		}
	}
	return res
}
