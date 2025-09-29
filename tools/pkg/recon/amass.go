package recon

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

/* ---------- data types ---------- */
type AmassResult struct {
	Domain     string          `json:"domain"`
	Subdomains []SubdomainInfo `json:"subdomains"`
	Sources    map[string]int  `json:"sources"`
	Count      int             `json:"count"`
	Timestamp  string          `json:"timestamp"`
	Command    string          `json:"command"`
	Mode       string          `json:"mode"`
	Status     string          `json:"status"`
	Debug      DebugInfo       `json:"debug"`
}

type SubdomainInfo struct {
	Name    string   `json:"name"`
	IPs     []string `json:"ips"`
	Sources []string `json:"sources"`
}

type DebugInfo struct {
	RawOutput   []string `json:"raw_output"`
	ParseErrors []string `json:"parse_errors"`
	TotalLines  int      `json:"total_lines"`
	ParsedLines int      `json:"parsed_lines"`
}

/* ---------- cobra command ---------- */
func NewAmassCommand() *cobra.Command {
	var (
		domain   string
		passive  bool
		active   bool
		timeout  int
		wordlist string
		debug    bool
	)
	cmd := &cobra.Command{
		Use:   "amass",
		Short: "Enhanced amass with debugging",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if passive && active {
				return fmt.Errorf("use either --passive or --active, not both")
			}
			if active {
				passive = false
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			result := performDebugAmass(domain, passive, timeout, wordlist, debug)
			outputJSON(result)
		},
	}
	cmd.Flags().StringVarP(&domain, "domain", "d", "", "Target domain")
	cmd.Flags().BoolVarP(&passive, "passive", "p", false, "Passive mode")
	cmd.Flags().BoolVarP(&active, "active", "a", false, "Active mode (forces -brute)")
	cmd.Flags().IntVarP(&timeout, "timeout", "t", 300, "Timeout (seconds)")
	cmd.Flags().StringVarP(&wordlist, "wordlist", "w", "", "Wordlist path")
	cmd.Flags().BoolVar(&debug, "debug", false, "Show debug info")
	_ = cmd.MarkFlagRequired("domain")
	return cmd
}

/* ---------- driver ---------- */
func performDebugAmass(domain string, passive bool, timeout int, wordlist string, debug bool) AmassResult {
	result := AmassResult{
		Domain:     domain,
		Subdomains: []SubdomainInfo{},
		Sources:    make(map[string]int),
		Timestamp:  time.Now().Format(time.RFC3339),
		Mode:       "passive",
		Command:    "",
		Status:     "running",
		Debug: DebugInfo{
			RawOutput:   []string{},
			ParseErrors: []string{},
			TotalLines:  0,
			ParsedLines: 0,
		},
	}
	seen := make(map[string]bool)

	if !passive {
		result.Mode = "active"
	}

	result = runAmassOnce(domain, passive, timeout, wordlist, result, seen, debug)
	if len(result.Subdomains) == 0 {
		result = fallbackIndicators(domain, result, seen, debug)
	}

	result.Status = "completed"
	result.Count = len(result.Subdomains)
	return result
}

/* ---------- single amass invocation ---------- */
func runAmassOnce(domain string, passive bool, timeout int, wordlist string, result AmassResult, seen map[string]bool, debug bool) AmassResult {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	args := []string{"enum", "-d", domain}
	if passive {
		args = append(args, "-passive")
	} else {
		args = append(args, "-active", "-brute")
		if wordlist != "" {
			args = append(args, "-w", wordlist)
		}
	}
	args = append(args, "-timeout", fmt.Sprintf("%d", timeout))

	cmd := exec.CommandContext(ctx, "amass", args...)
	out, err := cmd.CombinedOutput()
	output := string(out)

	if debug {
		result.Debug.RawOutput = append(result.Debug.RawOutput,
			fmt.Sprintf("Command: amass %s", strings.Join(args, " ")),
			fmt.Sprintf("Output:\n%s", output))
		result.Debug.TotalLines += len(strings.Split(output, "\n"))
	}

	if err != nil && len(out) == 0 {
		if debug {
			result.Debug.ParseErrors = append(result.Debug.ParseErrors, err.Error())
		}
		return result
	}

	result.Command = strings.Join(args, " ")
	return parseAmassOut(output, domain, "amass", result, seen, debug)
}

/* ---------- fallback indicators ---------- */
func fallbackIndicators(domain string, result AmassResult, seen map[string]bool, debug bool) AmassResult {
	indicators := []string{"www", "mail", "api", "admin", "portal", "secure", "cdn", "static", "app", "dev", "staging", "test"}
	for _, ind := range indicators {
		sub := ind + "." + domain
		if !seen[sub] {
			result.Subdomains = append(result.Subdomains, SubdomainInfo{
				Name:    sub,
				IPs:     []string{},
				Sources: []string{"indicator-fallback"},
			})
			seen[sub] = true
			result.Sources["indicator-fallback"]++
		}
	}
	return result
}

/* ---------- simple parser ---------- */
func parseAmassOut(output, domain, source string, result AmassResult, seen map[string]bool, debug bool) AmassResult {
	sc := bufio.NewScanner(strings.NewReader(output))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.Contains(line, "The enumeration has finished") {
			continue
		}
		result.Debug.ParsedLines++
		if strings.HasSuffix(line, "."+domain) && line != domain {
			if !seen[line] {
				result.Subdomains = append(result.Subdomains, SubdomainInfo{
					Name:    line,
					IPs:     []string{},
					Sources: []string{source},
				})
				seen[line] = true
				result.Sources[source]++
			}
			continue
		}
		for _, tok := range strings.Fields(line) {
			tok = strings.Trim(tok, "[](){}<>")
			if strings.HasSuffix(tok, "."+domain) && tok != domain && !seen[tok] {
				result.Subdomains = append(result.Subdomains, SubdomainInfo{
					Name:    tok,
					IPs:     []string{},
					Sources: []string{source},
				})
				seen[tok] = true
				result.Sources[source]++
			}
		}
	}
	return result
}

/* ---------- pretty print ---------- */
func outputJSON(v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}