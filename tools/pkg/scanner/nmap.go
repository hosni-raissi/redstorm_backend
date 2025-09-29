package scanner

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "net"
    "strings"
    "time"
    "os/exec"

    "github.com/spf13/cobra"
)

type NmapResult struct {
    Host     string      `json:"host"`
    Ports    []PortInfo  `json:"ports"`
    OS       string      `json:"os"`
    Services []Service   `json:"services"`
}

type PortInfo struct {
    Port     int    `json:"port"`
    Protocol string `json:"protocol"`
    State    string `json:"state"`
    Service  string `json:"service"`
    Version  string `json:"version"`
}

type Service struct {
    Name    string `json:"name"`
    Version string `json:"version"`
    Banner  string `json:"banner"`
}

func NewScanCommand() *cobra.Command {
    var target string
    var ports string
    var scanType string

    cmd := &cobra.Command{
        Use:   "scan",
        Short: "Network scanning with Nmap",
        Run: func(cmd *cobra.Command, args []string) {
            result := performNmapScan(target, ports, scanType)
            outputJSON(result)
        },
    }

    cmd.Flags().StringVarP(&target, "target", "t", "", "Target IP or domain")
    cmd.Flags().StringVarP(&ports, "ports", "p", "1-1000", "Port range to scan")
    cmd.Flags().StringVarP(&scanType, "type", "s", "syn", "Scan type (syn, tcp, udp)")
    cmd.MarkFlagRequired("target")

    return cmd
}

func performNmapScan(target, ports, scanType string) NmapResult {
    // First, check if nmap is available
    if _, err := exec.LookPath("nmap"); err != nil {
        log.Printf("Warning: nmap not found in PATH, using fallback scan")
        return performFallbackScan(target, ports, scanType)
    }


    // Build nmap command
    args := []string{"-p", ports, "-Pn"} // -Pn to skip host discovery
    
    // Add scan type
    switch scanType {
    case "syn":
        args = append(args, "-sS")
    case "tcp":
        args = append(args, "-sT")
    case "udp":
        args = append(args, "-sU")
    default:
        args = append(args, "-sS")
    }
    
    // Add service detection and OS detection
    args = append(args, "-sV", "--version-intensity", "0")
    
    // Add timing template for faster scans
    args = append(args, "-T4")
    
    // Set timeout
    args = append(args, "--host-timeout", "2m")
    
    // Add target
    args = append(args, target)

    log.Printf("Running nmap command: nmap %s", strings.Join(args, " "))

    // Execute nmap
    ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
    defer cancel()

    cmd := exec.CommandContext(ctx, "nmap", args...)
    output, err := cmd.CombinedOutput()
    
    if err != nil {
        log.Printf("nmap execution error: %v", err)
        log.Printf("nmap output: %s", string(output))
        return performFallbackScan(target, ports, scanType)
    }

    log.Printf("nmap raw output length: %d bytes", len(output))

    // Parse nmap output
    return parseNmapOutput(string(output), target)
}

func parseNmapOutput(output, target string) NmapResult {
    result := NmapResult{
        Host:     target,
        Ports:    []PortInfo{},
        Services: []Service{},
    }

    lines := strings.Split(output, "\n")
    
    for _, line := range lines {
        line = strings.TrimSpace(line)
        
        // Look for open ports
        if strings.Contains(line, "/tcp") || strings.Contains(line, "/udp") {
            parts := strings.Fields(line)
            if len(parts) >= 3 {
                portProto := strings.Split(parts[0], "/")
                if len(portProto) == 2 {
                    port := 0
                    fmt.Sscanf(portProto[0], "%d", &port)
                    
                    if port > 0 {
                        portInfo := PortInfo{
                            Port:     port,
                            Protocol: portProto[1],
                            State:    parts[1],
                            Service:  parts[2],
                            Version:  "",
                        }
                        
                        // Add version info if available
                        if len(parts) > 3 {
                            portInfo.Version = strings.Join(parts[3:], " ")
                        }
                        
                        result.Ports = append(result.Ports, portInfo)
                        
                        // Add to services
                        service := Service{
                            Name:    parts[2],
                            Version: portInfo.Version,
                            Banner:  portInfo.Version,
                        }
                        result.Services = append(result.Services, service)
                    }
                }
            }
        }
        
        // Look for OS detection
        if strings.Contains(line, "OS details:") || strings.Contains(line, "Running:") {
            result.OS = strings.TrimPrefix(line, "OS details:")
            result.OS = strings.TrimPrefix(result.OS, "Running:")
            result.OS = strings.TrimSpace(result.OS)
        }
    }
    
    log.Printf("Parsed %d open ports from nmap output", len(result.Ports))
    return result
}

func performFallbackScan(target, ports, scanType string) NmapResult {
    log.Printf("Performing fallback scan for %s", target)
    
    result := NmapResult{
        Host:     target,
        Ports:    []PortInfo{},
        Services: []Service{},
    }

    // Parse port range
    portList := parsePortRange(ports)
    log.Printf("Scanning %d ports in fallback mode", len(portList))

    for _, port := range portList {
        if isPortOpen(target, port) {
            service := detectService(target, port)
            
            portInfo := PortInfo{
                Port:     port,
                Protocol: "tcp",
                State:    "open",
                Service:  service.Name,
                Version:  service.Version,
            }
            result.Ports = append(result.Ports, portInfo)
            result.Services = append(result.Services, service)
        }
    }

    return result
}

func parsePortRange(portRange string) []int {
    ports := []int{}
    
    // Simple parser for "1-1000" format
    if strings.Contains(portRange, "-") {
        parts := strings.Split(portRange, "-")
        if len(parts) == 2 {
            var start, end int
            fmt.Sscanf(parts[0], "%d", &start)
            fmt.Sscanf(parts[1], "%d", &end)
            
            for i := start; i <= end && i <= start+100; i++ { // Limit to 100 ports for performance
                ports = append(ports, i)
            }
        }
    } else {
        // Single port or comma-separated
        if strings.Contains(portRange, ",") {
            // Handle comma-separated ports like "80,443,8080"
            portStrings := strings.Split(portRange, ",")
            for _, p := range portStrings {
                var port int
                fmt.Sscanf(strings.TrimSpace(p), "%d", &port)
                if port > 0 {
                    ports = append(ports, port)
                }
            }
        } else {
            // Single port
            var port int
            fmt.Sscanf(portRange, "%d", &port)
            if port > 0 {
                ports = append(ports, port)
            }
        }
    }
    
    return ports
}

func isPortOpen(host string, port int) bool {
    address := fmt.Sprintf("%s:%d", host, port)
    conn, err := net.DialTimeout("tcp", address, 2*time.Second)
    if err != nil {
        return false
    }
    conn.Close()
    return true
}

func detectService(host string, port int) Service {
    service := Service{
        Name:    "unknown",
        Version: "",
        Banner:  "",
    }

    // Common port to service mapping
    commonServices := map[int]string{
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn",
        143: "imap", 443: "https", 993: "imaps", 995: "pop3s",
        1723: "pptp", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
        5900: "vnc", 8080: "http-proxy", 8443: "https-alt",
    }

    if svc, ok := commonServices[port]; ok {
        service.Name = svc
    }

    // Try to grab banner
    banner := grabBanner(host, port)
    if banner != "" {
        service.Banner = banner
        service.Version = banner
    }

    return service
}

func grabBanner(host string, port int) string {
    address := fmt.Sprintf("%s:%d", host, port)
    conn, err := net.DialTimeout("tcp", address, 3*time.Second)
    if err != nil {
        return ""
    }
    defer conn.Close()

    // Send probe based on service
    probe := ""
    switch port {
    case 80, 8080:
        probe = "HEAD / HTTP/1.0\r\nHost: test\r\n\r\n"
    case 443:
        // For HTTPS, we'd need TLS, so just return common indicator
        return "SSL/TLS enabled"
    default:
        probe = "\r\n"
    }

    conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
    _, err = conn.Write([]byte(probe))
    if err != nil {
        return ""
    }

    conn.SetReadDeadline(time.Now().Add(2 * time.Second))
    buffer := make([]byte, 1024)
    n, err := conn.Read(buffer)
    if err != nil {
        return ""
    }

    return strings.TrimSpace(string(buffer[:n]))
}

func outputJSON(result interface{}) {
    jsonData, err := json.MarshalIndent(result, "", "  ")
    if err != nil {
        log.Printf("Error marshaling JSON: %v", err)
        return
    }
    fmt.Println(string(jsonData))
}