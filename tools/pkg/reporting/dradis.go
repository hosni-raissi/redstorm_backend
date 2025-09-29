package reporting

import (
    "context"
    "encoding/json"
    "fmt"
    "os/exec"
    "time"

    "github.com/spf13/cobra"
)

type DradisReport struct {
    ProjectName    string              `json:"project_name"`
    Target         string              `json:"target"`
    Findings       []Finding           `json:"findings"`
    Summary        ReportSummary       `json:"summary"`
    Recommendations []Recommendation   `json:"recommendations"`
    Timestamp      string              `json:"timestamp"`
    Format         string              `json:"format"`
}

type Finding struct {
    ID          string  `json:"id"`
    Title       string  `json:"title"`
    Severity    string  `json:"severity"`
    CVSSScore   float64 `json:"cvss_score"`
    Description string  `json:"description"`
    Evidence    string  `json:"evidence"`
    Solution    string  `json:"solution"`
    References  []string `json:"references"`
}

type ReportSummary struct {
    TotalFindings    int                    `json:"total_findings"`
    SeverityBreakdown map[string]int        `json:"severity_breakdown"`
    RiskLevel        string                 `json:"risk_level"`
    ComplianceStatus map[string]string      `json:"compliance_status"`
}

type Recommendation struct {
    Priority    string `json:"priority"`
    Category    string `json:"category"`
    Description string `json:"description"`
    Timeline    string `json:"timeline"`
}

func NewReportCommand() *cobra.Command {
    var target string
    var projectName string
    var format string
    var findings string

    cmd := &cobra.Command{
        Use:   "report",
        Short: "Generate collaborative security reports using Dradis",
        Run: func(cmd *cobra.Command, args []string) {
            result := generateDradisReport(target, projectName, format, findings)
            outputJSON(result)
        },
    }

    cmd.Flags().StringVarP(&target, "target", "t", "", "Target IP or domain")
    cmd.Flags().StringVarP(&projectName, "project", "p", "", "Project name")
    cmd.Flags().StringVarP(&format, "format", "f", "json", "Report format (json, pdf, html)")
    cmd.Flags().StringVarP(&findings, "findings", "F", "", "JSON file with findings")
    cmd.MarkFlagRequired("target")
    cmd.MarkFlagRequired("project")

    return cmd
}

func generateDradisReport(target, projectName, format, findingsFile string) DradisReport {
    report := DradisReport{
        ProjectName: projectName,
        Target:      target,
        Findings:    []Finding{},
        Format:      format,
        Timestamp:   time.Now().Format(time.RFC3339),
    }

    // Create Dradis project
    createProject(projectName)

    // Load findings from file or generate sample findings
    if findingsFile != "" {
        report.Findings = loadFindingsFromFile(findingsFile)
    } else {
        report.Findings = generateSampleFindings(target)
    }

    // Generate summary
    report.Summary = generateSummary(report.Findings)

    // Generate recommendations
    report.Recommendations = generateRecommendations(report.Findings)

    // Export report in requested format
    exportReport(report, format)

    return report
}

func createProject(projectName string) error {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    cmd := exec.CommandContext(ctx, "dradis", "project", "create", projectName)
    return cmd.Run()
}

func loadFindingsFromFile(filename string) []Finding {
    // Implementation to load findings from JSON file
    return []Finding{}
}

func generateSampleFindings(target string) []Finding {
    findings := []Finding{
        {
            ID:          "FINDING-001",
            Title:       "Open SSH Service",
            Severity:    "medium",
            CVSSScore:   5.3,
            Description: fmt.Sprintf("SSH service detected on %s", target),
            Evidence:    "Port 22/tcp open ssh OpenSSH 8.2p1",
            Solution:    "Ensure SSH is properly configured with key-based authentication",
            References:  []string{"CWE-287", "NIST-800-53-AC-2"},
        },
        {
            ID:          "FINDING-002",
            Title:       "HTTP Service Information Disclosure",
            Severity:    "low",
            CVSSScore:   3.1,
            Description: "HTTP server banner disclosure",
            Evidence:    "Server: Apache/2.4.41 (Ubuntu)",
            Solution:    "Configure server to hide version information",
            References:  []string{"CWE-200", "OWASP-A6"},
        },
    }

    return findings
}

func generateSummary(findings []Finding) ReportSummary {
    summary := ReportSummary{
        TotalFindings:     len(findings),
        SeverityBreakdown: make(map[string]int),
        ComplianceStatus:  make(map[string]string),
    }

    // Count severity levels
    for _, finding := range findings {
        summary.SeverityBreakdown[finding.Severity]++
    }

    // Determine overall risk level
    if summary.SeverityBreakdown["critical"] > 0 {
        summary.RiskLevel = "critical"
    } else if summary.SeverityBreakdown["high"] > 0 {
        summary.RiskLevel = "high"
    } else if summary.SeverityBreakdown["medium"] > 0 {
        summary.RiskLevel = "medium"
    } else {
        summary.RiskLevel = "low"
    }

    // Compliance status
    summary.ComplianceStatus["OWASP"] = "partial"
    summary.ComplianceStatus["NIST"] = "review_required"
    summary.ComplianceStatus["ISO27001"] = "non_compliant"

    return summary
}

func generateRecommendations(findings []Finding) []Recommendation {
    recommendations := []Recommendation{
        {
            Priority:    "high",
            Category:    "access_control",
            Description: "Implement multi-factor authentication for all administrative accounts",
            Timeline:    "immediate",
        },
        {
            Priority:    "medium",
            Category:    "network_security",
            Description: "Configure firewall rules to restrict unnecessary service exposure",
            Timeline:    "1-2 weeks",
        },
        {
            Priority:    "low",
            Category:    "information_disclosure",
            Description: "Configure services to minimize information disclosure",
            Timeline:    "1 month",
        },
    }

    return recommendations
}

func exportReport(report DradisReport, format string) error {
    ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
    defer cancel()

    switch format {
    case "pdf":
        cmd := exec.CommandContext(ctx, "dradis", "export", "pdf", report.ProjectName)
        return cmd.Run()
    case "html":
        cmd := exec.CommandContext(ctx, "dradis", "export", "html", report.ProjectName)
        return cmd.Run()
    default:
        // JSON format is handled by outputJSON
        return nil
    }
}

func outputJSON(result interface{}) {
    jsonData, _ := json.MarshalIndent(result, "", "  ")
    fmt.Println(string(jsonData))
}
