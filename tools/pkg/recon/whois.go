// recon/whois.go
package recon

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/likexian/whois"
	"github.com/spf13/cobra"
)

/* ---------- data types ---------- */
type WhoisResult struct {
	Domain         string   `json:"domain"`
	Registrar      string   `json:"registrar"`
	CreationDate   string   `json:"creation_date"`
	ExpirationDate string   `json:"expiration_date"`
	UpdatedDate    string   `json:"updated_date"`
	NameServers    []string `json:"name_servers"`
	Status         []string `json:"status"`
	Contacts       Contacts `json:"contacts"`
	DNSSEC         string   `json:"dnssec"`
	Raw            string   `json:"raw,omitempty"`
}

type Contacts struct {
	Registrant Contact `json:"registrant"`
	Admin      Contact `json:"admin"`
	Tech       Contact `json:"tech"`
}

type Contact struct {
	Name         string `json:"name"`
	Organization string `json:"organization"`
	Email        string `json:"email"`
	Phone        string `json:"phone"`
	Country      string `json:"country"`
}

/* ---------- cobra command ---------- */
func NewWhoisCommand() *cobra.Command {
	var domain string
	var debug bool

	cmd := &cobra.Command{
		Use:   "whois",
		Short: "WHOIS domain information lookup",
		Run: func(cmd *cobra.Command, args []string) {
			result := performWhoisLookup(domain, debug)
			outputJSON(result)
		},
	}

	cmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain to lookup")
	cmd.Flags().BoolVar(&debug, "debug", false, "Show raw WHOIS response")
	_ = cmd.MarkFlagRequired("domain")

	return cmd
}

/* ---------- core logic ---------- */
func performWhoisLookup(domain string, debug bool) WhoisResult {
	result := WhoisResult{
		Domain:      domain,
		NameServers: []string{},
		Status:      []string{},
		Contacts:    Contacts{},
	}

	// 1. try the library
	raw, err := whois.Whois(domain)
	if err != nil || strings.TrimSpace(raw) == "" {
		// 2. library failed or gave nothing → TCP fallback
		raw, _ = fallbackWhois(domain)
	}

	// 3. expose raw when requested
	if debug {
		result.Raw = raw
	}
	if strings.TrimSpace(raw) == "" {
		result.Raw = "empty response from all whois sources"
		return result
	}

	// 4. parse
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		key := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])
		if value == "" {
			continue
		}

		switch {
		case strings.Contains(key, "registrar") && result.Registrar == "":
			result.Registrar = value
		case anyOf(key, "created", "creation date", "registered on") && result.CreationDate == "":
			result.CreationDate = parseDate(value)
		case anyOf(key, "expires", "expiration", "expiry date", "registry expiry") && result.ExpirationDate == "":
			result.ExpirationDate = parseDate(value)
		case anyOf(key, "updated", "modified", "changed") && result.UpdatedDate == "":
			result.UpdatedDate = parseDate(value)
		case anyOf(key, "name server", "nserver") && !strings.EqualFold(value, "unsigned"):
			if !contains(result.NameServers, value) {
				result.NameServers = append(result.NameServers, value)
			}
		case strings.HasPrefix(key, "status") && !contains(result.Status, value):
			result.Status = append(result.Status, value)
		case anyOf(key, "dnssec", "ds data"):
			result.DNSSEC = value
		}
	}
	return result
}

/* ---------- helpers ---------- */
func anyOf(key string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(key, n) {
			return true
		}
	}
	return false
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func parseDate(dateStr string) string {
	formats := []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"02-Jan-2006",
		"2006.01.02",
		"02/01/2006",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, dateStr); err == nil {
			return t.Format("2006-01-02")
		}
	}
	return dateStr
}

/* ---------- multi-server TCP fallback ---------- */
func fallbackWhois(domain string) (string, error) {
	servers := []string{
		"whois.verisign-grs.com:43", // COM/NET
		"whois.iana.org:43",         // root
		"whois.nic.ru:43",           // RU, but accepts almost anything
		"whois.godaddy.com:43",      // big registrar
	}
	for _, srv := range servers {
		raw, err := tcpWhois(domain, srv)
		if err == nil && strings.TrimSpace(raw) != "" {
			return raw, nil
		}
	}
	return "", fmt.Errorf("all whois servers unreachable")
}

func tcpWhois(domain, server string) (string, error) {
	conn, err := net.DialTimeout("tcp", server, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_, _ = conn.Write([]byte(domain + "\r\n"))
	buf, err := io.ReadAll(conn)
	return string(buf), err
}
