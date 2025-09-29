package preengagement

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/Ullaakut/nmap/v3"
)

type AvailabilityResult struct {
	Target        string            `json:"target"`
	IsAvailable   bool              `json:"is_available"`
	ResponseTime  float64           `json:"response_time_ms"`
	FirewallRules map[string]string `json:"firewall_rules"`
	Methods       []string          `json:"methods_used"`
	Timestamp     string            `json:"timestamp"`
}

func NewPreEngagementCommand() *cobra.Command {
	var target string
	var timeout int

	cmd := &cobra.Command{
		Use:   "preengagement",
		Short: "Pre-engagement planning and target availability testing",
		Run: func(cmd *cobra.Command, args []string) {
			result := performAvailabilityTest(target, timeout)
			outputJSON(result)
		},
	}

	cmd.Flags().StringVarP(&target, "target", "t", "", "Target IP or domain")
	cmd.Flags().IntVarP(&timeout, "timeout", "T", 30, "Timeout in seconds")
	cmd.MarkFlagRequired("target")

	return cmd
}

func performAvailabilityTest(target string, timeout int) AvailabilityResult {
	result := AvailabilityResult{
		Target:        target,
		IsAvailable:   false,
		FirewallRules: make(map[string]string),
		Methods:       []string{},
		Timestamp:     time.Now().Format(time.RFC3339),
	}

	if fpingAvailable := testWithFping(target); fpingAvailable {
		result.IsAvailable = true
		result.Methods = append(result.Methods, "fping")
	}

	firewallRules := testFirewallWithHping3(target)
	result.FirewallRules = firewallRules
	if len(firewallRules) > 0 {
		result.Methods = append(result.Methods, "hping3")
	}

	nmapResults := testWithNmap(target, timeout)
	if nmapResults["available"] == "true" {
		result.IsAvailable = true
		result.Methods = append(result.Methods, "nmap")
	}

	// Merge firewall rules from nmap
	for k, v := range nmapResults {
		if k != "available" {
			result.FirewallRules[k] = v
		}
	}

	return result
}

func testWithFping(target string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "fping", "-c", "3", "-q", target)
	err := cmd.Run()
	return err == nil
}

func testFirewallWithHping3(target string) map[string]string {
	rules := make(map[string]string)

	tests := map[string][]string{
		"tcp_syn":   {"hping3", "-S", "-p", "80", "-c", "3", target},
		"tcp_fin":   {"hping3", "-F", "-p", "80", "-c", "3", target},
		"tcp_ack":   {"hping3", "-A", "-p", "80", "-c", "3", target},
		"icmp_ping": {"hping3", "-1", "-c", "3", target},
	}

	for testName, cmdArgs := range tests {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
		output, err := cmd.CombinedOutput()
		cancel()

		if err != nil {
			rules[testName] = "blocked"
		} else {
			outStr := string(output)
			switch {
			case strings.Contains(outStr, "100% packet loss"):
				rules[testName] = "filtered"
			case strings.Contains(outStr, "0% packet loss"):
				rules[testName] = "open"
			default:
				rules[testName] = "partial"
			}
		}
	}

	return rules
}

func testWithNmap(target string, timeout int) map[string]string {
	results := make(map[string]string)

	// cap nmap at 10 s regardless of CLI flag
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(target),
		nmap.WithPorts("22,80,443"),
		nmap.WithTimingTemplate(nmap.TimingAggressive), // -T5
	)
	if err != nil {
		results["error"] = fmt.Sprintf("scanner create: %v", err)
		return results
	}

	result, _, err := scanner.Run()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			results["error"] = "nmap scan timed out"
		} else {
			results["error"] = fmt.Sprintf("nmap scan: %v", err)
		}
		return results
	}

	if len(result.Hosts) == 0 || result.Hosts[0].Status.State != "up" {
		results["error"] = "host down"
		return results
	}

	h := result.Hosts[0]
	results["available"] = "true"
	results["host_state"] = "up"

	for _, p := range h.Ports {
		k := fmt.Sprintf("port_%d", p.ID)
		results[k] = string(p.State.State)
	}

	return results
}

func outputJSON(result interface{}) {
	jsonData, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(jsonData))
}