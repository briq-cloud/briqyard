package netw

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"text/template"
)

// Ruleset is what nftables must hold for the tenants on this host: masquerade their egress,
// let them reach the internet and their gateway's DNS, keep them apart from each other and from
// the host's other services.
type Ruleset struct {
	Egress  string
	Range   string
	Subnets []RulesetSubnet
	// DNATs are TCP endpoints delivered by nftables rather than the proxy (unused in v0).
	DNATs []DNAT
}

type RulesetSubnet struct {
	Bridge string
	Prefix string
}

type DNAT struct {
	HostPort int
	IP       string
	Port     int
}

var tmpl = template.Must(template.New("nft").Parse(`table inet briqyard
delete table inet briqyard
table inet briqyard {
	chain forward {
		type filter hook forward priority 0; policy accept;
		ct state established,related accept
		# a tenant never reaches another tenant, nor the host's own networks
		ip saddr {{.Range}} ip daddr {{.Range}} drop
		ip saddr {{.Range}} ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 } drop
		ip saddr {{.Range}} oifname "{{.Egress}}" accept
		iifname "{{.Egress}}" ip daddr {{.Range}} drop
	}
	chain input {
		type filter hook input priority 0; policy accept;
		ct state established,related accept
{{- range .Subnets}}
		# a machine may ask its gateway for DNS and the guest agent, nothing else of the host
		iifname "{{.Bridge}}" udp dport 53 accept
		iifname "{{.Bridge}}" tcp dport 53 accept
		iifname "{{.Bridge}}" icmp type echo-request accept
		iifname "{{.Bridge}}" drop
{{- end}}
	}
	chain postrouting {
		type nat hook postrouting priority 100; policy accept;
		ip saddr {{.Range}} oifname "{{.Egress}}" masquerade
	}
}
`))

// Render gives the nft script that installs the ruleset atomically.
func (r Ruleset) Render() (string, error) {
	var b bytes.Buffer
	if err := tmpl.Execute(&b, r); err != nil {
		return "", err
	}
	return b.String(), nil
}

// Apply installs the ruleset with nft. The script first declares the table so that the delete
// never fails on a fresh host, then replaces it in one transaction.
func (r Ruleset) Apply(ctx context.Context) error {
	script, err := r.Render()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft: %s", strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Remove deletes the table. Missing is success.
func Remove(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "nft", "delete", "table", "inet", "briqyard")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil && !strings.Contains(stderr.String(), "No such file") {
		return fmt.Errorf("nft: %s", strings.TrimSpace(stderr.String()))
	}
	return nil
}
