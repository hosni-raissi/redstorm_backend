package main

import (
    "encoding/json"
    "fmt"
    "log"

    "github.com/spf13/cobra"
    "redstorm-tools/pkg/scanner"
    "redstorm-tools/pkg/recon"
    "redstorm-tools/pkg/enumeration"
    "redstorm-tools/pkg/vulnerability"
    "redstorm-tools/pkg/preengagement"
    "redstorm-tools/pkg/exploitation"
    "redstorm-tools/pkg/postexploit"
)

var rootCmd = &cobra.Command{
    Use:   "redstorm-tools",
    Short: "RedStorm Security Tools Suite",
    Long:  "A comprehensive suite of security tools for penetration testing",
}

func main() {
    // Add subcommands
    rootCmd.AddCommand(
        preengagement.NewPreEngagementCommand(),
        scanner.NewScanCommand(),
        recon.NewReconCommand(),
        recon.NewAmassCommand(),
        recon.NewWhoisCommand(),
        enumeration.NewFuffCommand(),
        vulnerability.NewNucleiCommand(),
        vulnerability.NewWPScanCommand(),
        vulnerability.NewZAPCommand(),
        vulnerability.NewOpenVASCommand(),
        exploitation.NewExploitCommand(),
        postexploit.NewPostExploitCommand(),
    )

    if err := rootCmd.Execute(); err != nil {
        log.Fatal(err)
    }
}

// Common result structure for all tools
type ToolResult struct {
    Tool      string      `json:"tool"`
    Target    string      `json:"target"`
    Status    string      `json:"status"`
    Results   interface{} `json:"results"`
    Timestamp string      `json:"timestamp"`
    Error     string      `json:"error,omitempty"`
}

func OutputResult(result ToolResult) {
    jsonData, err := json.MarshalIndent(result, "", "  ")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(string(jsonData))
}
