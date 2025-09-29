// recon/recon.go
package recon

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/spf13/cobra"
)

/* ---------- types ---------- */
type SubdomainResult struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
	Count      int      `json:"count"`
}

/* ---------- command ---------- */
func NewReconCommand() *cobra.Command {
	var domain string
	var passive bool
	var codes string
	var debug bool

	cmd := &cobra.Command{
		Use:   "recon",
		Short: "Fast parallel recon: theHarvester + recon-ng + crt.sh → httpx filter",
		Run: func(cmd *cobra.Command, args []string) {
			result := performSubdomainEnum(domain, passive, codes, debug)
			outputJSON(result)
		},
	}

	cmd.Flags().StringVarP(&domain, "domain", "d", "", "Target domain")
	cmd.Flags().BoolVarP(&passive, "passive", "p", true, "Passive recon only")
	cmd.Flags().StringVarP(&codes, "codes", "c", "200,301,302,403", "HTTP codes to keep (comma-separated)")
	cmd.Flags().BoolVar(&debug, "debug", false, "Show raw harvester + recon-ng output")
	_ = cmd.MarkFlagRequired("domain")
	return cmd
}

/* ---------- worker ---------- */
func performSubdomainEnum(domain string, passive bool, codes string, debug bool) SubdomainResult {
	res := SubdomainResult{
		Domain:     domain,
		Subdomains: []string{},
	}

	// 1. check binaries
	if _, err := exec.LookPath("theHarvester"); err != nil {
		res.Subdomains = []string{"error: theHarvester not in PATH"}
		return res
	}
	if _, err := exec.LookPath("recon-ng"); err != nil {
		res.Subdomains = []string{"error: recon-ng not in PATH"}
		return res
	}

	// 2. temp dir
	tmpDir, err := ioutil.TempDir("", "recon-")
	if err != nil {
		res.Subdomains = []string{fmt.Sprintf("temp-dir-error: %v", err)}
		return res
	}
	defer os.RemoveAll(tmpDir)

	harvFile := filepath.Join(tmpDir, "harvester.txt")
	reconFile := filepath.Join(tmpDir, "reconng.txt")
	crtFile := filepath.Join(tmpDir, "crtsh.txt")
	finalFile := filepath.Join(tmpDir, "final.txt")

	// 3. parallel launch: harvester + recon-ng + crt.sh
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		runHarvester(domain, harvFile, passive, debug)
	}()
	go func() {
		defer wg.Done()
		runReconNg(domain, reconFile, passive, debug)
	}()
	go func() {
		defer wg.Done()
		runCrtSh(domain, crtFile, debug)
	}()

	wg.Wait()

	// 4. merge & dedup
	mergeCmd := fmt.Sprintf("sort -u %s %s %s > %s 2>/dev/null", harvFile, reconFile, crtFile, finalFile)
	exec.Command("bash", "-c", mergeCmd).Run()

	// 5. read hosts
	raw, _ := ioutil.ReadFile(finalFile)
	if debug {
		fmt.Fprintf(os.Stderr, "----- merged raw -----\n%s\n----- end -----\n", string(raw))
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")

	// 6. httpx filter
	res.Subdomains = probeWithHttpx(lines, codes, debug)
	res.Count = len(res.Subdomains)
	return res
}

/* ---------- theHarvester ---------- */
func runHarvester(domain, outFile string, passive bool, debug bool) {
	src := "all"
	if passive {
		src = "crtsh,bing,duckduckgo,yahoo,virustotal,shodan,netlas,hunter,dnsdumpster"
	}
	pipe := fmt.Sprintf(`theHarvester -d %s -b %s -f %s 2>&1 | grep -E '[a-z0-9.-]+\.%s$' | sort -u > %s`,
		domain, src, outFile, domain, outFile)
	cmd := exec.Command("bash", "-o", "pipefail", "-c", pipe)
	out, _ := cmd.CombinedOutput()
	if debug {
		fmt.Fprintf(os.Stderr, "----- harvester output -----\n%s\n----- end -----\n", string(out))
	}
}

/* ---------- recon-ng headless ---------- */
func runReconNg(domain, outFile string, passive bool, debug bool) {
	scriptPath := filepath.Join(filepath.Dir(outFile), "recon.script")
	script := fmt.Sprintf(`add domains %s
use recon/domains-hosts/hackertarget
run
use recon/domains-hosts/crtsh
run
use recon/domains-hosts/virustotal
run
show hosts
exit`, domain)
	if passive {
		script = strings.ReplaceAll(script, "use recon/domains-hosts/brute", "")
	}
	_ = ioutil.WriteFile(scriptPath, []byte(script), 0600)

	pipe := fmt.Sprintf(`recon-ng -r %s -w %s_temp 2>&1 | grep -E '^[[:space:]]*[a-z0-9.-]+\.%s$' | sed 's/^[[:space:]]*//' | sort -u > %s`,
		scriptPath, domain, domain, outFile)
	cmd := exec.Command("bash", "-o", "pipefail", "-c", pipe)
	out, _ := cmd.CombinedOutput()
	if debug {
		fmt.Fprintf(os.Stderr, "----- recon-ng output -----\n%s\n----- end -----\n", string(out))
	}
}

/* ---------- direct crt.sh fallback ---------- */
func runCrtSh(domain, outFile string, debug bool) {
	pipe := fmt.Sprintf(`curl -s "https://crt.sh/?q=%%.%s&output=json" 2>&1 | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//' | grep -E '[a-z0-9.-]+\.%s$' | sort -u > %s`,
		domain, domain, outFile)
	cmd := exec.Command("bash", "-c", pipe)
	out, _ := cmd.CombinedOutput()
	if debug {
		fmt.Fprintf(os.Stderr, "----- crt.sh output -----\n%s\n----- end -----\n", string(out))
	}
}

/* ---------- httpx batch probe ---------- */
func probeWithHttpx(hosts []string, codes string, debug bool) []string {
	if len(hosts) == 0 {
		return []string{} // ← never return nil
	}
	if _, err := exec.LookPath("httpx"); err != nil {
		return probeWithCurl(hosts, codes, debug) // fallback
	}

	cmd := exec.Command("httpx",
		"-sc", "-mc", codes,
		"-silent",
		"-timeout", "3",
		"-retry", "2")
	cmd.Stdin = strings.NewReader(strings.Join(hosts, "\n"))
	out, _ := cmd.Output()
	if debug {
		fmt.Fprintf(os.Stderr, "----- httpx raw -----\n%s\n----- end -----\n", string(out))
	}

	var alive []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// line format:  https://host [code]
		if u := strings.Fields(line); len(u) > 0 {
			alive = append(alive, strings.TrimSuffix(strings.TrimPrefix(u[0], "https://"), "/"))
		}
	}
	// if httpx found nothing, fall back to curl (quota-free)
	if len(alive) == 0 && len(hosts) > 0 {
		alive = probeWithCurl(hosts, codes, debug)
	}
	return alive
}

/* ---------- slow fallback (per-host curl) ---------- */
func probeWithCurl(hosts []string, codes string, debug bool) []string {
	want := make(map[string]bool)
	for _, c := range strings.Split(codes, ",") {
		want[strings.TrimSpace(c)] = true
	}
	var alive []string
	for _, h := range hosts {
		if !isValidDomain(h) {
			continue
		}
		code := curlStatus(h)
		if want[code] {
			alive = append(alive, h)
		}
	}
	return alive
}

func curlStatus(host string) string {
	cmd := exec.Command("curl", "-o", "/dev/null", "-w", "%{http_code}", "-s", "-I", "-m", "3", "https://"+host)
	out, _ := cmd.Output()
	return strings.TrimSpace(string(out))
}

/* ---------- domain validator ---------- */
func isValidDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 {
		return false
	}
	if strings.ContainsAny(d, " \t") {
		return false
	}
	if !strings.Contains(d, ".") {
		return false
	}
	if strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") ||
		strings.HasPrefix(d, "-") || strings.HasSuffix(d, "-") {
		return false
	}
	return true
}
