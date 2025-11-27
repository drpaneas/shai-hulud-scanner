package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// HistoryScanner checks shell history and credentials
type HistoryScanner struct {
	findings      []Finding
	findingsMutex sync.Mutex
	homeDir       string
}

// HistoryPattern represents a pattern to search for with metadata
type HistoryPattern struct {
	Pattern     *regexp.Regexp
	Description string
	Severity    string // "CRITICAL", "HIGH", "MEDIUM", "INFO"
	IsInfoOnly  bool   // If true, pattern might be from research/reading, not actual infection
}

var suspiciousHistoryPatterns = []HistoryPattern{
	// HIGH-CONFIDENCE: Actual malware execution commands
	{regexp.MustCompile(`(?i)node\s+.*setup_bun\.js`), "Executing setup_bun.js malware loader", "CRITICAL", false},
	{regexp.MustCompile(`(?i)node\s+.*bun_environment\.js`), "Executing bun_environment.js malware", "CRITICAL", false},
	{regexp.MustCompile(`(?i)bun\s+run\s+.*setup_bun`), "Running setup_bun with bun", "CRITICAL", false},
	{regexp.MustCompile(`curl.*bun\.sh/install.*\|\s*(ba)?sh`), "Piping bun installer to shell", "CRITICAL", false},
	{regexp.MustCompile(`irm\s+bun\.sh.*\|\s*iex`), "PowerShell bun installer execution", "CRITICAL", false},
	{regexp.MustCompile(`wget.*bun\.sh/install.*\|\s*(ba)?sh`), "Piping bun installer to shell", "CRITICAL", false},

	// HIGH-CONFIDENCE: Malware identifiers
	{regexp.MustCompile(`SHA1HULUD`), "Shai-Hulud malware identifier", "CRITICAL", false},
	{regexp.MustCompile(`Sha1-Hulud`), "Shai-Hulud malware identifier", "CRITICAL", false},
	{regexp.MustCompile(`The Second Coming`), "Shai-Hulud campaign name", "CRITICAL", false},
	{regexp.MustCompile(`\.truffler-cache`), "Malware cache directory reference", "HIGH", false},

	// MEDIUM-CONFIDENCE: Could be malware or research
	// These are downgraded because security researchers might have these in history
	{regexp.MustCompile(`curl.*trufflehog.*releases`), "Downloading trufflehog binary", "MEDIUM", true},
	{regexp.MustCompile(`npm\s+publish\s+--access\s+public`), "Public npm publish (worm propagation pattern)", "MEDIUM", true},

	// INFO-ONLY: Filename references (likely from research, not execution)
	// Only report if user explicitly wants verbose output
	// {regexp.MustCompile(`bun_environment\.js`), "Reference to bun_environment.js", "INFO", true},
	// {regexp.MustCompile(`setup_bun\.js`), "Reference to setup_bun.js", "INFO", true},

	// Exposed credentials in history (always flag these)
	{regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`), "GitHub Personal Access Token in history", "CRITICAL", false},
	{regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`), "GitHub OAuth Token in history", "CRITICAL", false},
	{regexp.MustCompile(`ghs_[a-zA-Z0-9]{36}`), "GitHub App Token in history", "CRITICAL", false},
	{regexp.MustCompile(`ghr_[a-zA-Z0-9]{36}`), "GitHub Refresh Token in history", "CRITICAL", false},
	{regexp.MustCompile(`glpat-[a-zA-Z0-9_-]{20}`), "GitLab Personal Access Token in history", "CRITICAL", false},
	{regexp.MustCompile(`glcbt-[a-zA-Z0-9_-]{20}`), "GitLab CI/CD Job Token in history", "CRITICAL", false},
	{regexp.MustCompile(`glrt-[a-zA-Z0-9_-]{20}`), "GitLab Runner Token in history", "CRITICAL", false},
	{regexp.MustCompile(`gldt-[a-zA-Z0-9_-]{20}`), "GitLab Deploy Token in history", "CRITICAL", false},

	// Anti-forensics / destructive commands (always flag)
	{regexp.MustCompile(`shred\s+-[a-z]*u`), "Secure file deletion command", "HIGH", false},
	{regexp.MustCompile(`cipher\s+/W:`), "Windows secure deletion command", "HIGH", false},
	{regexp.MustCompile(`del\s+/F\s+/Q\s+/S`), "Windows force recursive delete", "HIGH", false},
	{regexp.MustCompile(`rm\s+-rf\s+~/`), "Recursive delete of home directory", "CRITICAL", false},
	{regexp.MustCompile(`rm\s+-rf\s+\$HOME`), "Recursive delete of home directory", "CRITICAL", false},

	// System compromise indicators
	{regexp.MustCompile(`systemctl\s+stop\s+systemd-resolved`), "Disabling DNS resolver", "HIGH", false},
	{regexp.MustCompile(`iptables\s+-F`), "Flushing firewall rules", "HIGH", false},

	// Runner installation (context-dependent)
	{regexp.MustCompile(`actions-runner.*config.*--url.*--token`), "GitHub Actions runner configuration", "MEDIUM", true},
}

// NewHistoryScanner creates a new history scanner
func NewHistoryScanner() *HistoryScanner {
	homeDir, _ := os.UserHomeDir()
	return &HistoryScanner{
		findings: make([]Finding, 0),
		homeDir:  homeDir,
	}
}

func (hs *HistoryScanner) addFinding(finding Finding) {
	hs.findingsMutex.Lock()
	hs.findings = append(hs.findings, finding)
	hs.findingsMutex.Unlock()
}

// ScanShellHistory checks shell history files
func (hs *HistoryScanner) ScanShellHistory() {
	fmt.Printf("%s[HIST]%s Scanning shell history files...\n", colorCyan, colorReset)

	historyFiles := []string{
		filepath.Join(hs.homeDir, ".bash_history"),
		filepath.Join(hs.homeDir, ".zsh_history"),
		filepath.Join(hs.homeDir, ".history"),
		filepath.Join(hs.homeDir, ".sh_history"),
		filepath.Join(hs.homeDir, ".fish_history"),
		filepath.Join(hs.homeDir, ".local", "share", "fish", "fish_history"),
	}

	var wg sync.WaitGroup
	for _, histFile := range historyFiles {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			hs.scanHistoryFile(path)
		}(histFile)
	}
	wg.Wait()
}

func (hs *HistoryScanner) scanHistoryFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, hp := range suspiciousHistoryPatterns {
			if hp.Pattern.MatchString(line) {
				// Skip INFO-only patterns (likely from research)
				if hp.IsInfoOnly && hp.Severity == "INFO" {
					continue
				}

				findingType := "SUSPICIOUS_COMMAND"
				if hp.Severity == "CRITICAL" {
					findingType = "MALWARE_EXECUTION"
				}

				details := fmt.Sprintf("Command: %s", truncate(line, 100))
				if hp.IsInfoOnly {
					details += " (Note: Could be from security research)"
				}

				hs.addFinding(Finding{
					Type:        findingType,
					Severity:    hp.Severity,
					Path:        path,
					Description: fmt.Sprintf("%s (line %d)", hp.Description, lineNum),
					Details:     details,
				})
				break // Only report first matching pattern per line
			}
		}
	}
}

// ScanGitCredentials checks git credential stores
func (hs *HistoryScanner) ScanGitCredentials() {
	fmt.Printf("%s[HIST]%s Checking git credential stores...\n", colorCyan, colorReset)

	credFiles := []string{
		filepath.Join(hs.homeDir, ".git-credentials"),
		filepath.Join(hs.homeDir, ".gitconfig"),
	}

	for _, credFile := range credFiles {
		content, err := os.ReadFile(credFile)
		if err != nil {
			continue
		}

		if bytes.Contains(content, []byte("ghp_")) || bytes.Contains(content, []byte("gho_")) {
			hs.addFinding(Finding{
				Type:        "EXPOSED_CREDENTIAL",
				Severity:    "CRITICAL",
				Path:        credFile,
				Description: "GitHub token found in git credentials - may be compromised",
				Details:     "Rotate this token via https://github.com/settings/tokens",
			})
		}
		if bytes.Contains(content, []byte("glpat-")) {
			hs.addFinding(Finding{
				Type:        "EXPOSED_CREDENTIAL",
				Severity:    "CRITICAL",
				Path:        credFile,
				Description: "GitLab token found in git credentials - may be compromised",
				Details:     "Rotate this token via GitLab > Settings > Access Tokens",
			})
		}
	}
}

// ScanNpmrc checks npm tokens
func (hs *HistoryScanner) ScanNpmrc() {
	fmt.Printf("%s[HIST]%s Checking npm configuration...\n", colorCyan, colorReset)

	npmrcPaths := []string{
		filepath.Join(hs.homeDir, ".npmrc"),
		".npmrc",
	}

	for _, npmrc := range npmrcPaths {
		content, err := os.ReadFile(npmrc)
		if err != nil {
			continue
		}

		if bytes.Contains(content, []byte("//registry.npmjs.org/:_authToken=")) {
			hs.addFinding(Finding{
				Type:        "EXPOSED_CREDENTIAL",
				Severity:    "CRITICAL",
				Path:        npmrc,
				Description: "npm auth token found - may be compromised",
				Details:     "Rotate via: npm token revoke <token> && npm login",
			})
		}
	}
}

// ScanCloudCredentials checks cloud credential files
func (hs *HistoryScanner) ScanCloudCredentials() {
	fmt.Printf("%s[HIST]%s Checking cloud credentials...\n", colorCyan, colorReset)

	awsCredsPath := filepath.Join(hs.homeDir, ".aws", "credentials")
	if _, err := os.Stat(awsCredsPath); err == nil {
		hs.addFinding(Finding{
			Type:        "CREDENTIAL_FILE",
			Severity:    "HIGH",
			Path:        awsCredsPath,
			Description: "AWS credentials file exists - verify not compromised",
			Details:     "If infected, rotate via AWS Console > IAM > Security Credentials",
		})
	}

	gcpCredsPath := filepath.Join(hs.homeDir, ".config", "gcloud", "credentials.db")
	if _, err := os.Stat(gcpCredsPath); err == nil {
		hs.addFinding(Finding{
			Type:        "CREDENTIAL_FILE",
			Severity:    "HIGH",
			Path:        gcpCredsPath,
			Description: "GCP credentials file exists - verify not compromised",
			Details:     "If infected: gcloud auth revoke --all && gcloud auth login",
		})
	}

	azureCredsPath := filepath.Join(hs.homeDir, ".azure", "accessTokens.json")
	if _, err := os.Stat(azureCredsPath); err == nil {
		hs.addFinding(Finding{
			Type:        "CREDENTIAL_FILE",
			Severity:    "HIGH",
			Path:        azureCredsPath,
			Description: "Azure credentials file exists - verify not compromised",
			Details:     "If infected: az logout && az login",
		})
	}
}

// ScanGitHubCLI checks GitHub CLI config
func (hs *HistoryScanner) ScanGitHubCLI() {
	fmt.Printf("%s[HIST]%s Checking GitHub CLI configuration...\n", colorCyan, colorReset)

	ghConfigPath := filepath.Join(hs.homeDir, ".config", "gh", "hosts.yml")
	if _, err := os.Stat(ghConfigPath); err == nil {
		content, err := os.ReadFile(ghConfigPath)
		if err == nil && (bytes.Contains(content, []byte("oauth_token:")) || bytes.Contains(content, []byte("ghp_"))) {
			hs.addFinding(Finding{
				Type:        "CREDENTIAL_FILE",
				Severity:    "HIGH",
				Path:        ghConfigPath,
				Description: "GitHub CLI token found - verify not compromised",
				Details:     "If infected: gh auth logout && gh auth login",
			})
		}
	}
}

// ScanCIEnvironment checks if running in a CI/CD environment (malware target)
func (hs *HistoryScanner) ScanCIEnvironment() {
	fmt.Printf("%s[HIST]%s Checking CI/CD environment indicators...\n", colorCyan, colorReset)

	// CI/CD environment variables the malware specifically checks for
	ciEnvVars := []struct {
		name    string
		ciName  string
	}{
		{"GITHUB_ACTIONS", "GitHub Actions"},
		{"BUILDKITE", "Buildkite"},
		{"CIRCLE_SHA1", "CircleCI"},
		{"GITLAB_CI", "GitLab CI"},
		{"JENKINS_URL", "Jenkins"},
		{"TRAVIS", "Travis CI"},
		{"AZURE_PIPELINES", "Azure Pipelines"},
		{"TF_BUILD", "Azure DevOps"},
		{"AGENT_ID", "Azure DevOps Agent"},
	}

	for _, env := range ciEnvVars {
		if val := os.Getenv(env.name); val != "" {
			hs.addFinding(Finding{
				Type:        "CI_ENVIRONMENT",
				Severity:    "MEDIUM",
				Path:        "environment",
				Description: fmt.Sprintf("Running in %s CI/CD environment", env.ciName),
				Details:     fmt.Sprintf("%s=%s - Shai-Hulud malware specifically targets CI environments", env.name, truncate(val, 50)),
			})
		}
	}
}

// ScanGitRemotes checks for Shai-Hulud exfiltration repositories
func (hs *HistoryScanner) ScanGitRemotes() {
	fmt.Printf("%s[HIST]%s Checking git remotes for Shai-Hulud repos...\n", colorCyan, colorReset)

	// Check current directory and common project locations
	searchPaths := []string{
		".",
		filepath.Join(hs.homeDir, "projects"),
		filepath.Join(hs.homeDir, "Projects"),
		filepath.Join(hs.homeDir, "dev"),
		filepath.Join(hs.homeDir, "github"),
		filepath.Join(hs.homeDir, "work"),
	}

	// These are exfiltration repo patterns - NOT the scanner repo itself
	// The malware creates repos with descriptions like "Sha1Hulud: The Second Coming"
	maliciousRepoPatterns := []string{
		"Sha1-Hulud: The Second Coming",
		"Sha1-Hulud: The Continued Coming",
		"SHA1HULUD: The Second Coming",
		"The-Second-Coming",
		"The-Continued-Coming",
	}

	for _, searchPath := range searchPaths {
		_ = filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			// Limit depth
			rel, _ := filepath.Rel(searchPath, path)
			if strings.Count(rel, string(filepath.Separator)) > 3 {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			if info.IsDir() && info.Name() == ".git" {
				configPath := filepath.Join(path, "config")
				content, err := os.ReadFile(configPath)
				if err != nil {
					return filepath.SkipDir
				}

				for _, pattern := range maliciousRepoPatterns {
					if bytes.Contains(content, []byte(pattern)) {
						hs.addFinding(Finding{
							Type:        "MALICIOUS_REMOTE",
							Severity:    "CRITICAL",
							Path:        configPath,
							Description: fmt.Sprintf("Git repository with Shai-Hulud remote pattern: %s", pattern),
							Details:     "This may be an exfiltration repository created by the malware",
						})
					}
				}
				return filepath.SkipDir
			}

			if info.IsDir() && (info.Name() == "node_modules" || info.Name() == "vendor") {
				return filepath.SkipDir
			}

			return nil
		})
	}
}

// Run performs all history-based checks
func (hs *HistoryScanner) Run() []Finding {
	fmt.Printf("\n%s%s╔══════════════════════════════════════════════════════════════════╗%s\n", colorBold, colorPurple, colorReset)
	fmt.Printf("%s%s║  🐛 SHAI-HULUD v2 HISTORY SCANNER                                 ║%s\n", colorBold, colorPurple, colorReset)
	fmt.Printf("%s%s║  Checking shell history and credentials for malware activity      ║%s\n", colorBold, colorPurple, colorReset)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════╝%s\n", colorBold, colorPurple, colorReset)

	var wg sync.WaitGroup
	wg.Add(7)
	go func() { defer wg.Done(); hs.ScanShellHistory() }()
	go func() { defer wg.Done(); hs.ScanGitCredentials() }()
	go func() { defer wg.Done(); hs.ScanNpmrc() }()
	go func() { defer wg.Done(); hs.ScanCloudCredentials() }()
	go func() { defer wg.Done(); hs.ScanGitHubCLI() }()
	go func() { defer wg.Done(); hs.ScanCIEnvironment() }()
	go func() { defer wg.Done(); hs.ScanGitRemotes() }()
	wg.Wait()

	if len(hs.findings) > 0 {
		fmt.Printf("\n%s%s[HISTORY/CREDS FINDINGS] (%d detected)%s\n", colorBold, colorYellow, len(hs.findings), colorReset)
		fmt.Println(strings.Repeat("─", 70))

		for _, f := range hs.findings {
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
		fmt.Printf("%s[HIST]%s No suspicious patterns in shell history\n", colorGreen, colorReset)
	}

	return hs.findings
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

