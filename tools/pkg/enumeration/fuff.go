package enumeration

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

type pathItem struct {
	Name string `json:"name"`
}

type FuffResult struct {
	Domain     string     `json:"domain"`
	Subdomains []pathItem `json:"subdomains"`
	Count      int        `json:"count"`
}

/* ---------- public cobra command ---------- */
func NewFuffCommand() *cobra.Command {
	var (
		domain   string
		wordlist string
	)
	cmd := &cobra.Command{
		Use:   "fuff",
		Short: "Active path brute-force via ffuf (https://DOMAIN/<word>)",
		Run: func(cmd *cobra.Command, args []string) {
			result := performPathBrute(domain, wordlist)
			outputJSON(result)
		},
	}
	cmd.Flags().StringVarP(&domain, "domain", "d", "", "Target domain (example.com)")
	cmd.Flags().StringVarP(&wordlist, "wordlist", "w", "", "Path to wordlist for path brute-force")
	_ = cmd.MarkFlagRequired("domain")
	_ = cmd.MarkFlagRequired("wordlist")
	return cmd
}

/* ---------- core logic ---------- */
func performPathBrute(domain, wordlist string) FuffResult {
	res := FuffResult{Domain: domain}

	if _, err := exec.LookPath("ffuf"); err != nil {
		res.Subdomains = []pathItem{{Name: "error: ffuf not installed or not in PATH"}}
		return res
	}
    absWordlist, _ := filepath.Abs(wordlist) // ✅ absolute
	args := []string{
		"-u", fmt.Sprintf("https://%s/FUZZ", domain),
		"-w", absWordlist,
		"-mc", "200,204,301,302,307,401,403",
		"-s",
		"-of", "csv",
	}
	out, err := exec.Command("ffuf", args...).Output()
	if err != nil {
		//res.Subdomains = []pathItem{{Name: fmt.Sprintf("ffuf-error: %v", err)}}
		res.Subdomains = []pathItem{}
		return res
	}

	paths := parseFfufCSVLines(string(out))
	items := make([]pathItem, len(paths))
	for i, p := range paths {
		items[i] = pathItem{Name: p}
	}
	res.Subdomains = items
	res.Count = len(items)
	return res
}

/* ---------- helpers ---------- */
func parseFfufCSVLines(csv string) []string {
	var hits []string
	sc := bufio.NewScanner(strings.NewReader(csv))
	for sc.Scan() {
    line := strings.TrimSpace(sc.Text())
    if line == "" || strings.HasPrefix(line, "input") {
        continue
    }
    parts := strings.Split(line, ",")
    if len(parts) > 0 && !strings.Contains(parts[0], "error:") {
        hits = append(hits, parts[0])
    }
    }
	return hits
}

func outputJSON(v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}