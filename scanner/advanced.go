package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// AdvancedScanner performs deep analysis for Shai-Hulud indicators
// Based on analysis from: GitLab, Wiz, SentinelOne, StepSecurity, Tenable, Mend.io
type AdvancedScanner struct {
	findings      []Finding
	findingsMutex sync.Mutex
	homeDir       string
}

// Malware-specific patterns from technical reports
var (
	// Triple Base64 encoding pattern (used for exfiltration)
	base64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/]{100,}={0,2}$`)

	// GitHub token patterns
	githubPATPattern   = regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`)
	githubOAuthPattern = regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`)
	githubAppPattern   = regexp.MustCompile(`ghs_[a-zA-Z0-9]{36}`)
	githubRefresh      = regexp.MustCompile(`ghr_[a-zA-Z0-9]{36}`)

	// GitLab token patterns
	gitlabPATPattern    = regexp.MustCompile(`glpat-[a-zA-Z0-9_-]{20}`)
	gitlabCIPattern     = regexp.MustCompile(`glcbt-[a-zA-Z0-9_-]{20}`)
	gitlabRunnerPattern = regexp.MustCompile(`glrt-[a-zA-Z0-9_-]{20}`)

	// npm token pattern
	npmTokenPattern = regexp.MustCompile(`npm_[a-zA-Z0-9]{36}`)

	// AWS patterns
	awsAccessKey = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	awsSecretKey = regexp.MustCompile(`[a-zA-Z0-9+/]{40}`)

	// Malware-specific strings from Mend.io and SentinelOne analysis
	malwareSignatures = [][]byte{
		[]byte("Sha1-Hulud"),
		[]byte("SHA1HULUD"),
		[]byte("The Second Coming"),
		[]byte("The Continued Coming"),
		[]byte("downloadAndSetupBun"),
		[]byte("bun_environment"),
		[]byte("setup_bun"),
		[]byte("truffleSecrets"),
		[]byte("aL0()"),                              // Main malware function from deobfuscated code
		[]byte("fetchToken"),                         // Token harvesting function
		[]byte("scanFilesystem"),                     // TruffleHog scanning function
		[]byte("createRepo"),                         // Exfiltration repo creation
		[]byte("updatePackage"),                      // Worm propagation function
		[]byte("dq()"),                               // GitHub API class from obfuscated code
		[]byte("cipher /W:"),                         // Windows secure deletion
		[]byte("shred -uvz"),                         // Linux secure deletion
		[]byte("del /F /Q /S"),                       // Windows file deletion
		[]byte("RUNNER_TRACKING_ID: 0"),              // GitHub Actions runner marker
		[]byte("runs-on: self-hosted"),               // Self-hosted runner
		[]byte("discussion.body"),                    // Injection point
		[]byte("Add Discusion"),                      // Typo from malware (intentional marker)
		[]byte("actions/runners/registration-token"), // Runner registration

		// Token recycling patterns (searches other Shai-Hulud repos for tokens)
		[]byte("recycleToken"),
		[]byte("findShaiHuludRepos"),
		[]byte("extractTokenFromRepo"),

		// Azure DevOps exploitation
		[]byte("AGENT_BUILDDIRECTORY"),
		[]byte("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI"),
		[]byte("AZURE_DEVOPS_EXT_PAT"),

		// Docker privilege escalation
		[]byte("docker run --privileged"),
		[]byte("--net=host"),
		[]byte("-v /:/host"),

		// Network security bypass
		[]byte("systemctl stop systemd-resolved"),
		[]byte("iptables -F"),
		[]byte("iptables --flush"),

		// Worm propagation
		[]byte("npm publish --access public"),
		[]byte("npm version patch"),
	}

	// Obfuscation patterns (common in the 10MB bun_environment.js)
	obfuscationPatterns = [][]byte{
		[]byte("_0x"),          // Hex variable obfuscation
		[]byte("['\\x"),        // Hex string encoding
		[]byte("atob("),        // Base64 decode
		[]byte("Buffer.from("), // Node.js base64
		[]byte("eval("),        // Dynamic code execution
		[]byte("Function("),    // Dynamic function creation
	}

	// Network exfiltration indicators
	exfilDomains = []string{
		"webhook.site",
		"requestbin.com",
		"pipedream.net",
		"hookbin.com",
		"beeceptor.com",
	}
)

// NewAdvancedScanner creates a new advanced scanner
func NewAdvancedScanner() *AdvancedScanner {
	homeDir, _ := os.UserHomeDir()
	return &AdvancedScanner{
		findings: make([]Finding, 0),
		homeDir:  homeDir,
	}
}

func (as *AdvancedScanner) addFinding(finding Finding) {
	as.findingsMutex.Lock()
	as.findings = append(as.findings, finding)
	as.findingsMutex.Unlock()
}

// ScanForObfuscatedPayloads checks for heavily obfuscated JavaScript files
// Only scans node_modules directories for speed
func (as *AdvancedScanner) ScanForObfuscatedPayloads(rootPath string) {
	fmt.Printf("%s[ADV]%s Scanning for obfuscated malware payloads...\n", colorCyan, colorReset)

	// Only check specific locations where malware would be
	searchPaths := []string{
		filepath.Join(rootPath, "node_modules"),
		filepath.Join(as.homeDir, "node_modules"),
	}

	// Also find node_modules in common project locations
	projectDirs := []string{
		filepath.Join(as.homeDir, "projects"),
		filepath.Join(as.homeDir, "Projects"),
		filepath.Join(as.homeDir, "dev"),
		filepath.Join(as.homeDir, "Development"),
		filepath.Join(as.homeDir, "code"),
		filepath.Join(as.homeDir, "Code"),
		filepath.Join(as.homeDir, "github"),
		filepath.Join(as.homeDir, "GitHub"),
		filepath.Join(as.homeDir, "work"),
		filepath.Join(as.homeDir, "Work"),
	}

	for _, projDir := range projectDirs {
		if _, err := os.Stat(projDir); err == nil {
			// Quick scan for node_modules at depth 2
			entries, _ := os.ReadDir(projDir)
			for _, entry := range entries {
				if entry.IsDir() {
					nmPath := filepath.Join(projDir, entry.Name(), "node_modules")
					if _, err := os.Stat(nmPath); err == nil {
						searchPaths = append(searchPaths, nmPath)
					}
				}
			}
		}
	}

	checked := 0
	for _, searchPath := range searchPaths {
		if _, err := os.Stat(searchPath); os.IsNotExist(err) {
			continue
		}

		// Quick walk with early termination
		_ = filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			// Skip deep directories
			rel, _ := filepath.Rel(searchPath, path)
			if strings.Count(rel, string(filepath.Separator)) > 3 {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			if info.IsDir() {
				return nil
			}

			// Check for suspiciously large JS files (bun_environment.js is ~10MB)
			if strings.HasSuffix(path, ".js") && info.Size() > 5*1024*1024 {
				as.checkLargeJSFile(path, info.Size())
			}

			// Also check for the specific malware files by name
			name := filepath.Base(path)
			if name == "bun_environment.js" || name == "setup_bun.js" {
				as.addFinding(Finding{
					Type:        "MALICIOUS_FILE",
					Severity:    "CRITICAL",
					Path:        path,
					Description: fmt.Sprintf("Found %s - Shai-Hulud malware file", name),
					Details:     "This is a known malware component.",
				})
			}

			checked++
			if checked > 10000 { // Limit to prevent slowdown
				return filepath.SkipAll
			}

			return nil
		})
	}
}

func (as *AdvancedScanner) checkLargeJSFile(path string, size int64) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()

	// Read first 64KB for pattern analysis
	buf := make([]byte, 64*1024)
	n, _ := file.Read(buf)
	content := buf[:n]

	obfuscationScore := 0
	malwareScore := 0
	var details []string

	// Check for obfuscation patterns
	for _, pattern := range obfuscationPatterns {
		if bytes.Contains(content, pattern) {
			obfuscationScore++
		}
	}

	// Check for malware signatures
	for _, sig := range malwareSignatures {
		if bytes.Contains(content, sig) {
			malwareScore++
			details = append(details, fmt.Sprintf("Contains: %s", string(sig)))
		}
	}

	if obfuscationScore >= 3 || malwareScore >= 2 {
		severity := "HIGH"
		if malwareScore >= 2 {
			severity = "CRITICAL"
		}

		as.addFinding(Finding{
			Type:        "OBFUSCATED_PAYLOAD",
			Severity:    severity,
			Path:        path,
			Description: fmt.Sprintf("Suspicious large obfuscated JS file (%.2f MB)", float64(size)/(1024*1024)),
			Details:     fmt.Sprintf("Obfuscation score: %d, Malware score: %d. %s", obfuscationScore, malwareScore, strings.Join(details, "; ")),
		})
	}
}

// ScanForExfiltratedData checks for base64-encoded credential dumps
// Only checks specific likely locations for speed
func (as *AdvancedScanner) ScanForExfiltratedData(rootPath string) {
	fmt.Printf("%s[ADV]%s Scanning for exfiltrated credential data...\n", colorCyan, colorReset)

	suspiciousFiles := []string{
		"cloud.json",
		"contents.json",
		"environment.json",
		"truffleSecrets.json",
	}

	// Check in common locations only
	searchDirs := []string{
		rootPath,
		as.homeDir,
		filepath.Join(as.homeDir, ".github"),
		filepath.Join(rootPath, ".github"),
		filepath.Join(rootPath, "node_modules"),
	}

	for _, dir := range searchDirs {
		for _, filename := range suspiciousFiles {
			path := filepath.Join(dir, filename)
			if _, err := os.Stat(path); err == nil {
				as.analyzeExfilFile(path)
			}
		}
	}
}

func (as *AdvancedScanner) analyzeExfilFile(path string) {
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}

	// Check if content looks like base64 encoded data
	contentStr := strings.TrimSpace(string(content))
	if base64Pattern.MatchString(contentStr) {
		as.addFinding(Finding{
			Type:        "SUSPICIOUS_ENCODED_FILE",
			Severity:    "HIGH",
			Path:        path,
			Description: "File contains large Base64 encoded data",
			Details:     "This file matches the pattern of encoded exfiltration data.",
		})
	}

	// Check for triple Base64 encoding (malware characteristic)
	decoded1, err1 := base64.StdEncoding.DecodeString(contentStr)
	if err1 == nil {
		decoded2, err2 := base64.StdEncoding.DecodeString(string(decoded1))
		if err2 == nil {
			_, err3 := base64.StdEncoding.DecodeString(string(decoded2))
			if err3 == nil {
				as.addFinding(Finding{
					Type:        "EXFILTRATED_DATA",
					Severity:    "CRITICAL",
					Path:        path,
					Description: "Triple Base64 encoded data found - Shai-Hulud exfiltration signature",
					Details:     "This file contains credential data encoded using the malware's characteristic triple Base64 encoding.",
				})
				return
			}
		}
	}

	// Check for credential patterns in the file
	if githubPATPattern.Match(content) || githubOAuthPattern.Match(content) ||
		githubAppPattern.Match(content) || githubRefresh.Match(content) {
		as.addFinding(Finding{
			Type:        "EXPOSED_CREDENTIAL",
			Severity:    "CRITICAL",
			Path:        path,
			Description: "GitHub token found in suspicious file",
			Details:     "This file may contain exfiltrated GitHub credentials.",
		})
	}

	if awsAccessKey.Match(content) || awsSecretKey.Match(content) {
		as.addFinding(Finding{
			Type:        "EXPOSED_CREDENTIAL",
			Severity:    "CRITICAL",
			Path:        path,
			Description: "AWS credentials found in suspicious file",
			Details:     "This file may contain exfiltrated AWS credentials.",
		})
	}

	// Check for known exfiltration domains
	for _, domain := range exfilDomains {
		if strings.Contains(contentStr, domain) {
			as.addFinding(Finding{
				Type:        "EXFIL_DOMAIN",
				Severity:    "CRITICAL",
				Path:        path,
				Description: fmt.Sprintf("Exfiltration domain '%s' found in file", domain),
				Details:     "This file references a known data exfiltration service.",
			})
			break
		}
	}
}

// ScanGitHubRunners checks for malicious self-hosted runners
func (as *AdvancedScanner) ScanGitHubRunners() {
	fmt.Printf("%s[ADV]%s Checking for malicious GitHub Actions runners...\n", colorCyan, colorReset)

	// Check for runner installation directories (quick stat checks only)
	runnerPaths := []string{
		filepath.Join(as.homeDir, "actions-runner"),
		filepath.Join(as.homeDir, ".actions-runner"),
	}

	// Only check /opt if we have access (avoid slow permission checks)
	if _, err := os.Stat("/opt"); err == nil {
		runnerPaths = append(runnerPaths, "/opt/actions-runner")
	}

	for _, runnerPath := range runnerPaths {
		info, err := os.Stat(runnerPath)
		if err != nil || !info.IsDir() {
			continue
		}

		// Check .runner file for SHA1HULUD name
		runnerConfig := filepath.Join(runnerPath, ".runner")
		content, err := os.ReadFile(runnerConfig)
		if err == nil {
			if bytes.Contains(content, []byte("SHA1HULUD")) || bytes.Contains(content, []byte("Sha1-Hulud")) {
				as.addFinding(Finding{
					Type:        "MALICIOUS_RUNNER",
					Severity:    "CRITICAL",
					Path:        runnerPath,
					Description: "Malicious GitHub Actions runner 'SHA1HULUD' detected",
					Details:     "This runner was installed by the malware for persistent backdoor access.",
				})
				continue
			}
		}

		// Check for the runner regardless of name
		as.addFinding(Finding{
			Type:        "SUSPICIOUS_RUNNER",
			Severity:    "HIGH",
			Path:        runnerPath,
			Description: "GitHub Actions self-hosted runner installation found",
			Details:     "Verify this runner is legitimate. Shai-Hulud installs runners for backdoor access.",
		})
	}

	// Check running processes for runner (quick check)
	as.checkRunningRunners()
}

func (as *AdvancedScanner) checkRunningRunners() {
	// Use timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "pgrep", "-fl", "Runner.Listener")
	output, err := cmd.Output()
	if ctx.Err() != nil {
		return // Timed out, skip
	}
	if err == nil && len(output) > 0 {
		as.addFinding(Finding{
			Type:        "RUNNING_RUNNER",
			Severity:    "HIGH",
			Path:        "process",
			Description: "GitHub Actions runner process is currently running",
			Details:     strings.TrimSpace(string(output)),
		})
	}
}

// ScanWorkflows checks GitHub workflows for injection vulnerabilities
func (as *AdvancedScanner) ScanWorkflows(rootPath string) {
	fmt.Printf("%s[ADV]%s Scanning GitHub workflows for backdoor patterns...\n", colorCyan, colorReset)

	workflowsDir := filepath.Join(rootPath, ".github", "workflows")
	if _, err := os.Stat(workflowsDir); os.IsNotExist(err) {
		return
	}

	_ = filepath.Walk(workflowsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		if strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml") {
			as.analyzeWorkflow(path)
		}

		return nil
	})
}

func (as *AdvancedScanner) analyzeWorkflow(path string) {
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var issues []string

	// Check for self-hosted runner (potential backdoor)
	if bytes.Contains(content, []byte("runs-on: self-hosted")) {
		issues = append(issues, "Uses self-hosted runner")
	}

	// Check for discussion trigger with injection
	if bytes.Contains(content, []byte("on:")) && bytes.Contains(content, []byte("discussion")) {
		if bytes.Contains(content, []byte("github.event.discussion.body")) ||
			bytes.Contains(content, []byte("github.event.discussion.title")) {
			issues = append(issues, "Discussion body/title injection vulnerability")
		}
	}

	// Check for command injection patterns
	injectionPatterns := []string{
		"${{ github.event.",
		"echo ${{",
		"run: ${{",
	}
	for _, pattern := range injectionPatterns {
		if bytes.Contains(content, []byte(pattern)) {
			// Check if it's properly escaped
			if !bytes.Contains(content, []byte("toJSON(")) {
				issues = append(issues, fmt.Sprintf("Potential injection: %s", pattern))
			}
		}
	}

	// Check for malware-specific markers
	if bytes.Contains(content, []byte("Add Discusion")) || // Typo from malware
		bytes.Contains(content, []byte("RUNNER_TRACKING_ID: 0")) ||
		bytes.Contains(content, []byte("SHA1HULUD")) {
		issues = append(issues, "Contains Shai-Hulud malware markers")
	}

	if len(issues) > 0 {
		severity := "MEDIUM"
		if len(issues) >= 2 || strings.Contains(strings.Join(issues, ""), "Shai-Hulud") {
			severity = "CRITICAL"
		}

		as.addFinding(Finding{
			Type:        "SUSPICIOUS_WORKFLOW",
			Severity:    severity,
			Path:        path,
			Description: "GitHub workflow with suspicious patterns",
			Details:     strings.Join(issues, "; "),
		})
	}
}

// ScanEnvironmentFiles checks for leaked environment variables
func (as *AdvancedScanner) ScanEnvironmentFiles() {
	fmt.Printf("%s[ADV]%s Scanning for exposed environment files...\n", colorCyan, colorReset)

	envFiles := []string{
		filepath.Join(as.homeDir, ".env"),
		filepath.Join(as.homeDir, ".env.local"),
		".env",
		".env.local",
		".env.production",
		".env.development",
	}

	for _, envFile := range envFiles {
		if content, err := os.ReadFile(envFile); err == nil {
			as.checkEnvFileForSecrets(envFile, content)
		}
	}
}

func (as *AdvancedScanner) checkEnvFileForSecrets(path string, content []byte) {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	lineNum := 0
	var exposedSecrets []string

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip comments and empty lines
		if strings.HasPrefix(strings.TrimSpace(line), "#") || len(strings.TrimSpace(line)) == 0 {
			continue
		}

		// Check for various token patterns
		if githubPATPattern.MatchString(line) || githubOAuthPattern.MatchString(line) ||
			githubAppPattern.MatchString(line) || githubRefresh.MatchString(line) {
			exposedSecrets = append(exposedSecrets, fmt.Sprintf("GitHub token (line %d)", lineNum))
		}
		if gitlabPATPattern.MatchString(line) || gitlabCIPattern.MatchString(line) ||
			gitlabRunnerPattern.MatchString(line) {
			exposedSecrets = append(exposedSecrets, fmt.Sprintf("GitLab token (line %d)", lineNum))
		}
		if npmTokenPattern.MatchString(line) {
			exposedSecrets = append(exposedSecrets, fmt.Sprintf("npm token (line %d)", lineNum))
		}
		if awsAccessKey.MatchString(line) || awsSecretKey.MatchString(line) {
			exposedSecrets = append(exposedSecrets, fmt.Sprintf("AWS credential (line %d)", lineNum))
		}
		if strings.Contains(line, "AZURE_") && strings.Contains(line, "SECRET") {
			exposedSecrets = append(exposedSecrets, fmt.Sprintf("Azure secret (line %d)", lineNum))
		}
		if strings.Contains(line, "GCP_") || strings.Contains(line, "GOOGLE_") {
			if strings.Contains(line, "KEY") || strings.Contains(line, "SECRET") {
				exposedSecrets = append(exposedSecrets, fmt.Sprintf("GCP credential (line %d)", lineNum))
			}
		}
	}

	if len(exposedSecrets) > 0 {
		as.addFinding(Finding{
			Type:        "EXPOSED_SECRETS",
			Severity:    "CRITICAL",
			Path:        path,
			Description: fmt.Sprintf("Environment file with %d exposed secrets", len(exposedSecrets)),
			Details:     fmt.Sprintf("Found: %s. These may have been harvested by the malware.", strings.Join(exposedSecrets, ", ")),
		})
	}
}

// ScanProcesses checks for suspicious running processes
func (as *AdvancedScanner) ScanProcesses() {
	fmt.Printf("%s[ADV]%s Checking for suspicious processes...\n", colorCyan, colorReset)

	suspiciousProcesses := []string{
		"trufflehog",
		"bun_environment",
		"setup_bun",
	}

	// Use timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	for _, proc := range suspiciousProcesses {
		cmd := exec.CommandContext(ctx, "pgrep", "-fl", proc)
		output, err := cmd.Output()
		if ctx.Err() != nil {
			return // Timed out
		}
		if err == nil && len(output) > 0 {
			severity := "CRITICAL"

			as.addFinding(Finding{
				Type:        "SUSPICIOUS_PROCESS",
				Severity:    severity,
				Path:        "process:" + proc,
				Description: fmt.Sprintf("Suspicious process '%s' is running", proc),
				Details:     strings.TrimSpace(string(output)),
			})
		}
	}
}

// Run performs all advanced scans
func (as *AdvancedScanner) Run(rootPath string) []Finding {
	fmt.Printf("\n%s%s╔══════════════════════════════════════════════════════════════════╗%s\n", colorBold, colorPurple, colorReset)
	fmt.Printf("%s%s║  🐛 SHAI-HULUD v2 ADVANCED SCANNER                                ║%s\n", colorBold, colorPurple, colorReset)
	fmt.Printf("%s%s║  Deep scan: obfuscation, runners, workflows, exfiltration         ║%s\n", colorBold, colorPurple, colorReset)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════╝%s\n", colorBold, colorPurple, colorReset)

	var wg sync.WaitGroup

	wg.Add(6)
	go func() { defer wg.Done(); as.ScanForObfuscatedPayloads(rootPath) }()
	go func() { defer wg.Done(); as.ScanForExfiltratedData(rootPath) }()
	go func() { defer wg.Done(); as.ScanGitHubRunners() }()
	go func() { defer wg.Done(); as.ScanWorkflows(rootPath) }()
	go func() { defer wg.Done(); as.ScanEnvironmentFiles() }()
	go func() { defer wg.Done(); as.ScanProcesses() }()

	wg.Wait()

	if len(as.findings) > 0 {
		fmt.Printf("\n%s%s[ADVANCED FINDINGS] (%d detected)%s\n", colorBold, colorRed, len(as.findings), colorReset)
		fmt.Println(strings.Repeat("─", 70))

		for _, f := range as.findings {
			severityColor := colorYellow
			if f.Severity == "CRITICAL" {
				severityColor = colorRed
			}
			fmt.Printf("%s[%s]%s %s\n", severityColor, f.Severity, colorReset, f.Description)
			fmt.Printf("  %s📁 Path:%s %s\n", colorCyan, colorReset, f.Path)
			if f.Details != "" {
				fmt.Printf("  %s📝 Details:%s %s\n", colorCyan, colorReset, f.Details)
			}
			fmt.Println()
		}
	} else {
		fmt.Printf("%s[ADV]%s No additional malware indicators found\n", colorGreen, colorReset)
	}

	return as.findings
}
