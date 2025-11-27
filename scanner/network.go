package scanner

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// NetworkIndicators contains patterns to detect Shai-Hulud network activity
var NetworkIndicators = struct {
	Domains     []string
	URLPatterns []*regexp.Regexp
	DNSPatterns []string
}{
	Domains: []string{
		"bun.sh",
		"raw.githubusercontent.com",
		"api.github.com",
	},
	URLPatterns: []*regexp.Regexp{
		regexp.MustCompile(`bun\.sh/install`),
		regexp.MustCompile(`github\.com/.+/trufflehog/releases`),
		regexp.MustCompile(`api\.github\.com/repos/.+/contents`),
		regexp.MustCompile(`api\.github\.com/user/repos`),
		regexp.MustCompile(`raw\.githubusercontent\.com/.+/contents\.json`),
		regexp.MustCompile(`api\.github\.com/.+/actions/runners`),
	},
	DNSPatterns: []string{
		"bun.sh",
		"githubusercontent.com",
	},
}

// NetworkFinding represents a detected network indicator
type NetworkFinding struct {
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Indicator   string    `json:"indicator"`
	Description string    `json:"description"`
	Details     string    `json:"details,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// NetworkScanner handles network-based detection
type NetworkScanner struct {
	findings      []NetworkFinding
	findingsMutex sync.Mutex
	interfaces    []string
}

// NewNetworkScanner creates a new network scanner
func NewNetworkScanner() *NetworkScanner {
	return &NetworkScanner{
		findings: make([]NetworkFinding, 0),
	}
}

func (ns *NetworkScanner) addFinding(finding NetworkFinding) {
	ns.findingsMutex.Lock()
	ns.findings = append(ns.findings, finding)
	ns.findingsMutex.Unlock()
}

// CheckActiveConnections checks current network connections
func (ns *NetworkScanner) CheckActiveConnections() {
	fmt.Printf("%s[NET]%s Checking active network connections...\n", colorCyan, colorReset)

	connections := ns.getActiveConnections()

	for _, conn := range connections {
		for _, domain := range NetworkIndicators.Domains {
			if strings.Contains(conn, domain) {
				ns.addFinding(NetworkFinding{
					Type:        "ACTIVE_CONNECTION",
					Severity:    "HIGH",
					Indicator:   domain,
					Description: fmt.Sprintf("Active connection to suspicious domain: %s", domain),
					Details:     conn,
					Timestamp:   time.Now(),
				})
			}
		}
	}

	fmt.Printf("%s[NET]%s Checked %d active connections\n", colorGreen, colorReset, len(connections))
}

func (ns *NetworkScanner) getActiveConnections() []string {
	var connections []string

	cmd := exec.Command("lsof", "-i", "-n", "-P")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "ESTABLISHED") || strings.Contains(line, "SYN_SENT") {
				connections = append(connections, line)
			}
		}
		return connections
	}

	cmd = exec.Command("netstat", "-an")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "ESTABLISHED") {
				connections = append(connections, line)
			}
		}
	}

	return connections
}

// CheckDNSCache checks DNS cache for suspicious queries
func (ns *NetworkScanner) CheckDNSCache() {
	fmt.Printf("%s[NET]%s Checking DNS cache...\n", colorCyan, colorReset)

	cmd := exec.Command("dscacheutil", "-cachedump", "-entries")
	output, _ := cmd.Output()

	outputStr := string(output)
	for _, pattern := range NetworkIndicators.DNSPatterns {
		if strings.Contains(outputStr, pattern) {
			ns.addFinding(NetworkFinding{
				Type:        "DNS_CACHE",
				Severity:    "MEDIUM",
				Indicator:   pattern,
				Description: fmt.Sprintf("Suspicious domain in DNS cache: %s", pattern),
				Timestamp:   time.Now(),
			})
		}
	}
}

// CheckRecentConnections checks for recent suspicious connections
func (ns *NetworkScanner) CheckRecentConnections() {
	fmt.Printf("%s[NET]%s Checking recent connection history...\n", colorCyan, colorReset)

	cmd := exec.Command("log", "show", "--predicate",
		`processImagePath CONTAINS "curl" OR processImagePath CONTAINS "wget" OR processImagePath CONTAINS "node"`,
		"--last", "1h", "--style", "compact")

	output, err := cmd.Output()
	if err != nil {
		return
	}

	outputStr := string(output)
	for _, pattern := range NetworkIndicators.URLPatterns {
		if pattern.MatchString(outputStr) {
			ns.addFinding(NetworkFinding{
				Type:        "RECENT_CONNECTION",
				Severity:    "HIGH",
				Indicator:   pattern.String(),
				Description: "Suspicious URL pattern in recent system logs",
				Timestamp:   time.Now(),
			})
		}
	}
}

// ScanNetworkInterfaces lists available network interfaces
func (ns *NetworkScanner) ScanNetworkInterfaces() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var names []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			names = append(names, iface.Name)
		}
	}

	ns.interfaces = names
	return names
}

// PrintNetworkFindings displays network scan results
func (ns *NetworkScanner) PrintNetworkFindings() {
	if len(ns.findings) == 0 {
		fmt.Printf("%s[NET]%s No suspicious network activity detected\n", colorGreen, colorReset)
		return
	}

	fmt.Printf("\n%s%s[NETWORK FINDINGS] (%d detected)%s\n", colorBold, colorRed, len(ns.findings), colorReset)
	fmt.Println(strings.Repeat("─", 70))

	for _, f := range ns.findings {
		severityColor := colorYellow
		if f.Severity == "HIGH" || f.Severity == "CRITICAL" {
			severityColor = colorRed
		}

		fmt.Printf("%s[%s]%s %s\n", severityColor, f.Severity, colorReset, f.Description)
		fmt.Printf("  %s🌐 Indicator:%s %s\n", colorCyan, colorReset, f.Indicator)
		if f.Details != "" {
			fmt.Printf("  %s📝 Details:%s %s\n", colorCyan, colorReset, f.Details)
		}
		fmt.Println()
	}
}

// Run performs all network checks
func (ns *NetworkScanner) Run() []NetworkFinding {
	fmt.Printf("\n%s%s╔══════════════════════════════════════════════════════════════════╗%s\n", colorBold, colorPurple, colorReset)
	fmt.Printf("%s%s║  🌐 NETWORK TRAFFIC ANALYSIS                                      ║%s\n", colorBold, colorPurple, colorReset)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════╝%s\n", colorBold, colorPurple, colorReset)

	ifaces := ns.ScanNetworkInterfaces()
	fmt.Printf("%s[NET]%s Available interfaces: %v\n", colorBlue, colorReset, ifaces)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); ns.CheckActiveConnections() }()
	go func() { defer wg.Done(); ns.CheckDNSCache() }()
	go func() { defer wg.Done(); ns.CheckRecentConnections() }()
	wg.Wait()

	ns.PrintNetworkFindings()
	return ns.findings
}

