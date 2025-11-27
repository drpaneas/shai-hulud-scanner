package scanner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// PersistenceScanner checks for malware persistence mechanisms
type PersistenceScanner struct {
	findings      []Finding
	findingsMutex sync.Mutex
	homeDir       string
}

// Suspicious patterns in git hooks
var gitHookPatterns = [][]byte{
	[]byte("curl"),
	[]byte("wget"),
	[]byte("bun.sh"),
	[]byte("eval"),
	[]byte("base64"),
	[]byte("nc "), // netcat
	[]byte("ncat"),
	[]byte("/dev/tcp"),
	[]byte("bash -i"),
	[]byte("python -c"),
	[]byte("node -e"),
	[]byte("ghp_"), // GitHub token
	[]byte("npm_"), // npm token
	[]byte("AKIA"), // AWS key
	[]byte("bun_environment"),
	[]byte("setup_bun"),
	[]byte("trufflehog"),
}

// Suspicious patterns in shell config files
var shellRCPatterns = []*regexp.Regexp{
	regexp.MustCompile(`alias\s+(npm|node|git|curl|wget)\s*=`), // command hijacking
	regexp.MustCompile(`export\s+PATH=.*:[^:]*\$HOME[^:]*:`),   // PATH injection
	regexp.MustCompile(`eval\s+\$\(curl`),                      // remote code exec
	regexp.MustCompile(`eval\s+\$\(wget`),
	regexp.MustCompile(`source\s+<\(curl`),
	regexp.MustCompile(`\|\s*bash`), // pipe to bash
	regexp.MustCompile(`\|\s*sh`),
	regexp.MustCompile(`base64\s+-d`),         // base64 decode
	regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`), // embedded tokens
	regexp.MustCompile(`npm_[a-zA-Z0-9]{36}`),
}

// NewPersistenceScanner creates a new persistence scanner
func NewPersistenceScanner() *PersistenceScanner {
	homeDir, _ := os.UserHomeDir()
	return &PersistenceScanner{
		findings: make([]Finding, 0),
		homeDir:  homeDir,
	}
}

func (ps *PersistenceScanner) addFinding(finding Finding) {
	ps.findingsMutex.Lock()
	ps.findings = append(ps.findings, finding)
	ps.findingsMutex.Unlock()
}

// ScanGitHooks checks all .git/hooks directories for malicious hooks
func (ps *PersistenceScanner) ScanGitHooks() {
	fmt.Printf("%s[PERSIST]%s Scanning git hooks for backdoors...\n", colorCyan, colorReset)

	// Common git hook names that execute automatically
	dangerousHooks := []string{
		"pre-commit", "post-commit", "pre-push", "post-checkout",
		"post-merge", "pre-rebase", "post-rewrite", "prepare-commit-msg",
		"commit-msg", "pre-receive", "post-receive", "update",
	}

	// Search for .git directories
	searchPaths := []string{
		ps.homeDir,
		filepath.Join(ps.homeDir, "projects"),
		filepath.Join(ps.homeDir, "Projects"),
		filepath.Join(ps.homeDir, "dev"),
		filepath.Join(ps.homeDir, "Development"),
		filepath.Join(ps.homeDir, "code"),
		filepath.Join(ps.homeDir, "github"),
		filepath.Join(ps.homeDir, "GitHub"),
		filepath.Join(ps.homeDir, "work"),
		filepath.Join(ps.homeDir, "repos"),
	}

	checked := 0
	for _, searchPath := range searchPaths {
		if _, err := os.Stat(searchPath); os.IsNotExist(err) {
			continue
		}

		filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || !info.IsDir() {
				return nil
			}

			// Limit depth and count
			rel, _ := filepath.Rel(searchPath, path)
			if strings.Count(rel, string(filepath.Separator)) > 4 {
				return filepath.SkipDir
			}

			if info.Name() == ".git" {
				hooksDir := filepath.Join(path, "hooks")
				ps.checkHooksDir(hooksDir, dangerousHooks)
				checked++
				if checked > 500 {
					return filepath.SkipAll
				}
				return filepath.SkipDir
			}

			// Skip node_modules and other heavy dirs
			if info.Name() == "node_modules" || info.Name() == "vendor" {
				return filepath.SkipDir
			}

			return nil
		})
	}

	fmt.Printf("%s[PERSIST]%s Checked %d git repositories\n", colorGreen, colorReset, checked)
}

func (ps *PersistenceScanner) checkHooksDir(hooksDir string, hookNames []string) {
	for _, hookName := range hookNames {
		hookPath := filepath.Join(hooksDir, hookName)
		content, err := os.ReadFile(hookPath)
		if err != nil {
			continue
		}

		// Check for suspicious patterns
		var suspicious []string
		for _, pattern := range gitHookPatterns {
			if bytes.Contains(content, pattern) {
				suspicious = append(suspicious, string(pattern))
			}
		}

		if len(suspicious) > 0 {
			ps.addFinding(Finding{
				Type:        "MALICIOUS_GIT_HOOK",
				Severity:    "CRITICAL",
				Path:        hookPath,
				Description: fmt.Sprintf("Suspicious git hook '%s' with dangerous patterns", hookName),
				Details:     fmt.Sprintf("Contains: %s", strings.Join(suspicious, ", ")),
			})
		}
	}
}

// ScanSSHAuthorizedKeys checks for unauthorized SSH keys
func (ps *PersistenceScanner) ScanSSHAuthorizedKeys() {
	fmt.Printf("%s[PERSIST]%s Checking SSH authorized_keys for backdoors...\n", colorCyan, colorReset)

	authKeysPath := filepath.Join(ps.homeDir, ".ssh", "authorized_keys")
	content, err := os.ReadFile(authKeysPath)
	if err != nil {
		return
	}

	lines := strings.Split(string(content), "\n")
	suspiciousKeys := 0

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for suspicious key comments/names
		lowerLine := strings.ToLower(line)
		suspicious := false
		var reason string

		// Keys with no comment are suspicious
		parts := strings.Fields(line)
		if len(parts) == 2 {
			suspicious = true
			reason = "SSH key with no identifying comment"
		}

		// Keys with suspicious names
		suspiciousNames := []string{"root", "admin", "test", "temp", "backup", "default", "ubuntu", "ec2"}
		for _, name := range suspiciousNames {
			if strings.Contains(lowerLine, name) && !strings.Contains(lowerLine, "@") {
				suspicious = true
				reason = fmt.Sprintf("SSH key with suspicious name containing '%s'", name)
			}
		}

		// Keys added very recently (check file mtime vs current time)
		info, _ := os.Stat(authKeysPath)
		if info != nil {
			if time.Since(info.ModTime()) < 7*24*time.Hour {
				suspicious = true
				reason = "authorized_keys modified within last 7 days"
			}
		}

		if suspicious {
			suspiciousKeys++
			keyPreview := line
			if len(keyPreview) > 80 {
				keyPreview = keyPreview[:40] + "..." + keyPreview[len(keyPreview)-30:]
			}
			ps.addFinding(Finding{
				Type:        "SUSPICIOUS_SSH_KEY",
				Severity:    "HIGH",
				Path:        authKeysPath,
				Description: fmt.Sprintf("Potentially unauthorized SSH key (line %d)", i+1),
				Details:     fmt.Sprintf("%s. Key: %s", reason, keyPreview),
			})
		}
	}
}

// ScanCronJobs checks for malicious cron jobs
func (ps *PersistenceScanner) ScanCronJobs() {
	fmt.Printf("%s[PERSIST]%s Checking cron jobs for persistence...\n", colorCyan, colorReset)

	// User crontab
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "crontab", "-l")
	output, err := cmd.Output()
	if err == nil && len(output) > 0 {
		ps.analyzeCronOutput(string(output), "user crontab")
	}

	// User cron directories
	cronDirs := []string{
		filepath.Join(ps.homeDir, ".cron"),
		"/etc/cron.d",
		"/var/spool/cron/crontabs",
	}

	for _, dir := range cronDirs {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() {
					path := filepath.Join(dir, entry.Name())
					if content, err := os.ReadFile(path); err == nil {
						ps.analyzeCronOutput(string(content), path)
					}
				}
			}
		}
	}

	// macOS LaunchAgents
	if runtime.GOOS == "darwin" {
		ps.scanLaunchAgents()
	}

	// Linux systemd user services
	if runtime.GOOS == "linux" {
		ps.scanSystemdUserServices()
	}
}

func (ps *PersistenceScanner) analyzeCronOutput(content, source string) {
	suspiciousPatterns := []string{
		"curl", "wget", "nc ", "ncat", "python", "node -e",
		"bash -c", "/dev/tcp", "base64", "eval",
		"bun.sh", "githubusercontent.com", "pastebin",
	}

	lines := strings.Split(content, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		for _, pattern := range suspiciousPatterns {
			if strings.Contains(strings.ToLower(line), pattern) {
				ps.addFinding(Finding{
					Type:        "SUSPICIOUS_CRON",
					Severity:    "CRITICAL",
					Path:        source,
					Description: fmt.Sprintf("Suspicious cron job (line %d)", i+1),
					Details:     fmt.Sprintf("Contains '%s': %s", pattern, truncate(line, 100)),
				})
				break
			}
		}
	}
}

func (ps *PersistenceScanner) scanLaunchAgents() {
	fmt.Printf("%s[PERSIST]%s Checking macOS LaunchAgents...\n", colorCyan, colorReset)

	launchAgentDirs := []string{
		filepath.Join(ps.homeDir, "Library", "LaunchAgents"),
		"/Library/LaunchAgents",
	}

	suspiciousPrograms := []string{
		"curl", "wget", "node", "python", "bash -c", "sh -c",
		"bun", "trufflehog", "/tmp/", "/var/tmp/",
	}

	for _, dir := range launchAgentDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".plist") {
				continue
			}

			path := filepath.Join(dir, entry.Name())
			content, err := os.ReadFile(path)
			if err != nil {
				continue
			}

			contentStr := string(content)
			for _, prog := range suspiciousPrograms {
				if strings.Contains(contentStr, prog) {
					ps.addFinding(Finding{
						Type:        "SUSPICIOUS_LAUNCHAGENT",
						Severity:    "HIGH",
						Path:        path,
						Description: fmt.Sprintf("LaunchAgent with suspicious program: %s", prog),
						Details:     fmt.Sprintf("File: %s", entry.Name()),
					})
					break
				}
			}
		}
	}
}

func (ps *PersistenceScanner) scanSystemdUserServices() {
	userServiceDir := filepath.Join(ps.homeDir, ".config", "systemd", "user")
	entries, err := os.ReadDir(userServiceDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".service") {
			continue
		}

		path := filepath.Join(userServiceDir, entry.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		contentStr := string(content)
		suspicious := []string{"curl", "wget", "nc ", "python -c", "node -e", "bash -c"}
		for _, s := range suspicious {
			if strings.Contains(contentStr, s) {
				ps.addFinding(Finding{
					Type:        "SUSPICIOUS_SYSTEMD",
					Severity:    "HIGH",
					Path:        path,
					Description: fmt.Sprintf("User systemd service with suspicious command: %s", s),
				})
				break
			}
		}
	}
}

// ScanShellConfigs checks shell RC files for malicious code
func (ps *PersistenceScanner) ScanShellConfigs() {
	fmt.Printf("%s[PERSIST]%s Checking shell configs for hijacking...\n", colorCyan, colorReset)

	shellConfigs := []string{
		filepath.Join(ps.homeDir, ".bashrc"),
		filepath.Join(ps.homeDir, ".bash_profile"),
		filepath.Join(ps.homeDir, ".profile"),
		filepath.Join(ps.homeDir, ".zshrc"),
		filepath.Join(ps.homeDir, ".zprofile"),
		filepath.Join(ps.homeDir, ".zshenv"),
		filepath.Join(ps.homeDir, ".config", "fish", "config.fish"),
	}

	for _, configPath := range shellConfigs {
		content, err := os.ReadFile(configPath)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(bytes.NewReader(content))
		lineNum := 0

		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			for _, pattern := range shellRCPatterns {
				if pattern.MatchString(line) {
					ps.addFinding(Finding{
						Type:        "SHELL_HIJACK",
						Severity:    "HIGH",
						Path:        configPath,
						Description: fmt.Sprintf("Suspicious pattern in shell config (line %d)", lineNum),
						Details:     fmt.Sprintf("Pattern: %s, Line: %s", pattern.String(), truncate(line, 80)),
					})
				}
			}
		}
	}
}

// ScanGlobalNpmPackages checks globally installed npm packages
func (ps *PersistenceScanner) ScanGlobalNpmPackages() {
	fmt.Printf("%s[PERSIST]%s Checking global npm packages...\n", colorCyan, colorReset)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "npm", "ls", "-g", "--depth=0", "--json")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	// Check for known malicious packages
	maliciousGlobal := []string{
		"bun_environment", "setup_bun", "trufflehog",
		"posthog-node", "kill-port", "shell-exec",
	}

	outputStr := string(output)
	for _, pkg := range maliciousGlobal {
		if strings.Contains(outputStr, pkg) {
			ps.addFinding(Finding{
				Type:        "MALICIOUS_GLOBAL_PACKAGE",
				Severity:    "CRITICAL",
				Path:        "npm global",
				Description: fmt.Sprintf("Potentially malicious global npm package: %s", pkg),
				Details:     "Run: npm ls -g to see full list",
			})
		}
	}
}

// ScanListeningPorts checks for suspicious listening ports
func (ps *PersistenceScanner) ScanListeningPorts() {
	fmt.Printf("%s[PERSIST]%s Checking for suspicious listening ports...\n", colorCyan, colorReset)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.CommandContext(ctx, "lsof", "-iTCP", "-sTCP:LISTEN", "-n", "-P")
	} else {
		cmd = exec.CommandContext(ctx, "ss", "-tlnp")
	}

	output, err := cmd.Output()
	if err != nil {
		return
	}

	// Suspicious processes that shouldn't be listening
	suspicious := []string{
		"nc", "ncat", "netcat", "socat",
		"python", "perl", "ruby", "php",
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		lowerLine := strings.ToLower(line)
		for _, proc := range suspicious {
			if strings.Contains(lowerLine, proc) {
				ps.addFinding(Finding{
					Type:        "SUSPICIOUS_LISTENER",
					Severity:    "HIGH",
					Path:        "network",
					Description: fmt.Sprintf("Suspicious process listening on network: %s", proc),
					Details:     truncate(line, 100),
				})
				break
			}
		}
	}
}

// ScanPATHHijacking checks for PATH manipulation
func (ps *PersistenceScanner) ScanPATHHijacking() {
	fmt.Printf("%s[PERSIST]%s Checking for PATH hijacking...\n", colorCyan, colorReset)

	pathEnv := os.Getenv("PATH")
	paths := strings.Split(pathEnv, ":")

	suspiciousPaths := []string{
		"/tmp", "/var/tmp", "/dev/shm",
		".npm", ".node", ".bun",
	}

	for _, p := range paths {
		// Check for suspicious directories in PATH
		for _, sus := range suspiciousPaths {
			if strings.Contains(p, sus) {
				ps.addFinding(Finding{
					Type:        "PATH_HIJACK",
					Severity:    "HIGH",
					Path:        p,
					Description: fmt.Sprintf("Suspicious directory in PATH: %s", p),
					Details:     "Attacker may have added this to intercept commands",
				})
			}
		}

		// Check for world-writable directories in PATH
		if info, err := os.Stat(p); err == nil {
			if info.Mode().Perm()&0002 != 0 {
				ps.addFinding(Finding{
					Type:        "PATH_HIJACK",
					Severity:    "CRITICAL",
					Path:        p,
					Description: fmt.Sprintf("World-writable directory in PATH: %s", p),
					Details:     "Any user can place malicious binaries here",
				})
			}
		}
	}
}

// ScanPackageLockIntegrity checks for tampered package-lock.json files
func (ps *PersistenceScanner) ScanPackageLockIntegrity() {
	fmt.Printf("%s[PERSIST]%s Checking package-lock.json integrity...\n", colorCyan, colorReset)

	// Known malicious package patterns that might be injected
	maliciousPatterns := []string{
		"bun_environment", "setup_bun", "trufflehog",
		"@aspect/rules_js", "postinstall", "preinstall",
	}

	// Search only in specific project directories (not entire home)
	searchPaths := []string{
		filepath.Join(ps.homeDir, "projects"),
		filepath.Join(ps.homeDir, "Projects"),
		filepath.Join(ps.homeDir, "dev"),
		filepath.Join(ps.homeDir, "github"),
		filepath.Join(ps.homeDir, "work"),
		filepath.Join(ps.homeDir, "code"),
	}

	checked := 0
	for _, searchPath := range searchPaths {
		if _, err := os.Stat(searchPath); os.IsNotExist(err) {
			continue
		}

		filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			// Limit depth first (for both files and dirs)
			rel, _ := filepath.Rel(searchPath, path)
			if strings.Count(rel, string(filepath.Separator)) > 3 {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			// Skip heavy directories
			if info.IsDir() {
				if info.Name() == "node_modules" || info.Name() == ".git" || info.Name() == "vendor" {
					return filepath.SkipDir
				}
				return nil
			}

			if info.Name() == "package-lock.json" {
				ps.checkPackageLock(path, maliciousPatterns)
				checked++
				if checked > 100 {
					return filepath.SkipAll
				}
			}

			return nil
		})
	}

	fmt.Printf("%s[PERSIST]%s Checked %d package-lock.json files\n", colorGreen, colorReset, checked)
}

func (ps *PersistenceScanner) checkPackageLock(path string, maliciousPatterns []string) {
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}

	// Check for malicious package names
	contentStr := string(content)
	for _, pattern := range maliciousPatterns {
		if strings.Contains(contentStr, pattern) {
			ps.addFinding(Finding{
				Type:        "SUSPICIOUS_LOCKFILE",
				Severity:    "HIGH",
				Path:        path,
				Description: fmt.Sprintf("package-lock.json contains suspicious pattern: %s", pattern),
				Details:     "Verify this dependency is legitimate",
			})
		}
	}

	// Parse and check for integrity hash mismatches (basic check)
	var lockFile map[string]interface{}
	if err := json.Unmarshal(content, &lockFile); err != nil {
		return
	}

	// Check if lockfileVersion is 3 (npm 7+) and look for suspicious resolved URLs
	if packages, ok := lockFile["packages"].(map[string]interface{}); ok {
		for pkgPath, pkgData := range packages {
			if pkg, ok := pkgData.(map[string]interface{}); ok {
				if resolved, ok := pkg["resolved"].(string); ok {
					// Check for non-npm registry URLs
					if resolved != "" && !strings.Contains(resolved, "registry.npmjs.org") &&
						!strings.Contains(resolved, "registry.yarnpkg.com") {
						ps.addFinding(Finding{
							Type:        "SUSPICIOUS_REGISTRY",
							Severity:    "CRITICAL",
							Path:        path,
							Description: fmt.Sprintf("Package from non-standard registry: %s", pkgPath),
							Details:     fmt.Sprintf("Resolved to: %s", truncate(resolved, 80)),
						})
					}
				}
			}
		}
	}
}

// ScanVSCodeExtensions checks for suspicious VS Code extensions
func (ps *PersistenceScanner) ScanVSCodeExtensions() {
	fmt.Printf("%s[PERSIST]%s Checking VS Code extensions...\n", colorCyan, colorReset)

	extensionDirs := []string{
		filepath.Join(ps.homeDir, ".vscode", "extensions"),
		filepath.Join(ps.homeDir, ".vscode-server", "extensions"),
		filepath.Join(ps.homeDir, ".cursor", "extensions"),
	}

	// Known suspicious extension patterns
	suspiciousPatterns := []string{
		"unknown-publisher",
		"test-extension",
		"malware",
		"keylogger",
		"credential",
		"password",
		"token-stealer",
	}

	for _, extDir := range extensionDirs {
		entries, err := os.ReadDir(extDir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			extName := strings.ToLower(entry.Name())

			// Check for suspicious names
			for _, pattern := range suspiciousPatterns {
				if strings.Contains(extName, pattern) {
					ps.addFinding(Finding{
						Type:        "SUSPICIOUS_VSCODE_EXT",
						Severity:    "HIGH",
						Path:        filepath.Join(extDir, entry.Name()),
						Description: fmt.Sprintf("Suspicious VS Code extension: %s", entry.Name()),
						Details:     "Verify this extension is legitimate",
					})
				}
			}

			// Check extension's package.json for suspicious activationEvents
			pkgJsonPath := filepath.Join(extDir, entry.Name(), "package.json")
			if content, err := os.ReadFile(pkgJsonPath); err == nil {
				contentStr := strings.ToLower(string(content))
				if strings.Contains(contentStr, "onfilesystem") ||
					strings.Contains(contentStr, "curl") ||
					strings.Contains(contentStr, "wget") ||
					strings.Contains(contentStr, "child_process") {
					ps.addFinding(Finding{
						Type:        "SUSPICIOUS_VSCODE_EXT",
						Severity:    "MEDIUM",
						Path:        pkgJsonPath,
						Description: fmt.Sprintf("Extension with suspicious capabilities: %s", entry.Name()),
						Details:     "Extension may have filesystem or process access",
					})
				}
			}
		}
	}
}

// ScanBrowserExtensions checks for suspicious browser extensions
func (ps *PersistenceScanner) ScanBrowserExtensions() {
	fmt.Printf("%s[PERSIST]%s Checking browser extensions...\n", colorCyan, colorReset)

	var extensionDirs []string

	if runtime.GOOS == "darwin" {
		extensionDirs = []string{
			// Chrome
			filepath.Join(ps.homeDir, "Library", "Application Support", "Google", "Chrome", "Default", "Extensions"),
			// Firefox
			filepath.Join(ps.homeDir, "Library", "Application Support", "Firefox", "Profiles"),
			// Edge
			filepath.Join(ps.homeDir, "Library", "Application Support", "Microsoft Edge", "Default", "Extensions"),
			// Brave
			filepath.Join(ps.homeDir, "Library", "Application Support", "BraveSoftware", "Brave-Browser", "Default", "Extensions"),
		}
	} else if runtime.GOOS == "linux" {
		extensionDirs = []string{
			// Chrome
			filepath.Join(ps.homeDir, ".config", "google-chrome", "Default", "Extensions"),
			// Firefox
			filepath.Join(ps.homeDir, ".mozilla", "firefox"),
			// Chromium
			filepath.Join(ps.homeDir, ".config", "chromium", "Default", "Extensions"),
		}
	}

	suspiciousPermissions := []string{
		"clipboardRead",
		"clipboardWrite",
		"webRequestBlocking",
		"nativeMessaging",
		"debugger",
		"<all_urls>",
		"*://*/*",
	}

	for _, extDir := range extensionDirs {
		if _, err := os.Stat(extDir); os.IsNotExist(err) {
			continue
		}

		// Walk extension directories looking for manifest.json
		filepath.Walk(extDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			// Limit depth
			rel, _ := filepath.Rel(extDir, path)
			if strings.Count(rel, string(filepath.Separator)) > 4 {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			if info.IsDir() {
				return nil
			}

			if info.Name() == "manifest.json" {
				content, err := os.ReadFile(path)
				if err != nil {
					return nil
				}

				contentStr := string(content)
				var suspicious []string

				for _, perm := range suspiciousPermissions {
					if strings.Contains(contentStr, perm) {
						suspicious = append(suspicious, perm)
					}
				}

				// Only flag if multiple suspicious permissions
				if len(suspicious) >= 3 {
					// Try to get extension name
					var manifest map[string]interface{}
					extName := "Unknown"
					if err := json.Unmarshal(content, &manifest); err == nil {
						if name, ok := manifest["name"].(string); ok {
							extName = name
						}
					}

					ps.addFinding(Finding{
						Type:        "SUSPICIOUS_BROWSER_EXT",
						Severity:    "MEDIUM",
						Path:        path,
						Description: fmt.Sprintf("Browser extension with broad permissions: %s", extName),
						Details:     fmt.Sprintf("Permissions: %s", strings.Join(suspicious, ", ")),
					})
				}
			}

			return nil
		})
	}
}

// ScanDockerContainers checks for suspicious Docker containers
func (ps *PersistenceScanner) ScanDockerContainers() {
	fmt.Printf("%s[PERSIST]%s Checking Docker containers...\n", colorCyan, colorReset)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check for running containers
	cmd := exec.CommandContext(ctx, "docker", "ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Command}}\t{{.Names}}")
	output, err := cmd.Output()
	if err != nil {
		return // Docker not installed or not running
	}

	suspiciousImages := []string{
		"alpine", "busybox", "ubuntu", "debian", // base images running alone
		"nc", "netcat", "socat", "nmap",
		"kali", "parrot", "blackarch",
	}

	suspiciousCommands := []string{
		"nc ", "ncat", "bash", "sh -c",
		"python", "perl", "ruby",
		"/bin/sh", "sleep",
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		lowerLine := strings.ToLower(line)

		// Check for suspicious images
		for _, img := range suspiciousImages {
			if strings.Contains(lowerLine, img) {
				ps.addFinding(Finding{
					Type:        "SUSPICIOUS_CONTAINER",
					Severity:    "MEDIUM",
					Path:        "docker",
					Description: fmt.Sprintf("Container with potentially suspicious image: %s", img),
					Details:     truncate(line, 100),
				})
				break
			}
		}

		// Check for suspicious commands
		for _, cmd := range suspiciousCommands {
			if strings.Contains(lowerLine, cmd) {
				ps.addFinding(Finding{
					Type:        "SUSPICIOUS_CONTAINER",
					Severity:    "HIGH",
					Path:        "docker",
					Description: fmt.Sprintf("Container running suspicious command: %s", cmd),
					Details:     truncate(line, 100),
				})
				break
			}
		}
	}

	// Check for containers with host network or privileged mode
	cmd = exec.CommandContext(ctx, "docker", "ps", "-q")
	containerIDs, err := cmd.Output()
	if err != nil {
		return
	}

	for _, id := range strings.Split(strings.TrimSpace(string(containerIDs)), "\n") {
		if id == "" {
			continue
		}

		inspectCmd := exec.CommandContext(ctx, "docker", "inspect", "--format",
			"{{.HostConfig.Privileged}} {{.HostConfig.NetworkMode}} {{.Name}}", id)
		inspectOut, err := inspectCmd.Output()
		if err != nil {
			continue
		}

		inspectStr := string(inspectOut)
		if strings.Contains(inspectStr, "true") {
			ps.addFinding(Finding{
				Type:        "PRIVILEGED_CONTAINER",
				Severity:    "CRITICAL",
				Path:        "docker",
				Description: "Privileged Docker container detected",
				Details:     fmt.Sprintf("Container: %s", truncate(inspectStr, 80)),
			})
		}
		if strings.Contains(inspectStr, "host") {
			ps.addFinding(Finding{
				Type:        "HOST_NETWORK_CONTAINER",
				Severity:    "HIGH",
				Path:        "docker",
				Description: "Docker container with host network access",
				Details:     fmt.Sprintf("Container: %s", truncate(inspectStr, 80)),
			})
		}
	}
}

// ScanLDPreload checks for LD_PRELOAD library injection
func (ps *PersistenceScanner) ScanLDPreload() {
	fmt.Printf("%s[PERSIST]%s Checking for LD_PRELOAD injection...\n", colorCyan, colorReset)

	// Check LD_PRELOAD environment variable
	ldPreload := os.Getenv("LD_PRELOAD")
	if ldPreload != "" {
		ps.addFinding(Finding{
			Type:        "LD_PRELOAD_INJECTION",
			Severity:    "CRITICAL",
			Path:        "environment",
			Description: "LD_PRELOAD environment variable is set",
			Details:     fmt.Sprintf("Value: %s - This can be used for library injection attacks", ldPreload),
		})
	}

	// Check /etc/ld.so.preload
	if content, err := os.ReadFile("/etc/ld.so.preload"); err == nil && len(content) > 0 {
		ps.addFinding(Finding{
			Type:        "LD_PRELOAD_INJECTION",
			Severity:    "CRITICAL",
			Path:        "/etc/ld.so.preload",
			Description: "System-wide LD_PRELOAD configuration found",
			Details:     fmt.Sprintf("Content: %s", truncate(string(content), 100)),
		})
	}

	// Check LD_LIBRARY_PATH for suspicious directories
	ldLibPath := os.Getenv("LD_LIBRARY_PATH")
	if ldLibPath != "" {
		suspicious := []string{"/tmp", "/var/tmp", "/dev/shm", ps.homeDir}
		for _, sus := range suspicious {
			if strings.Contains(ldLibPath, sus) {
				ps.addFinding(Finding{
					Type:        "SUSPICIOUS_LD_PATH",
					Severity:    "HIGH",
					Path:        "environment",
					Description: fmt.Sprintf("LD_LIBRARY_PATH contains suspicious directory: %s", sus),
					Details:     fmt.Sprintf("Full path: %s", ldLibPath),
				})
			}
		}
	}

	// Check for suspicious shared libraries in common locations
	if runtime.GOOS == "linux" {
		suspiciousLibDirs := []string{
			"/tmp",
			"/var/tmp",
			"/dev/shm",
			filepath.Join(ps.homeDir, ".local", "lib"),
		}

		for _, dir := range suspiciousLibDirs {
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}

			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".so") ||
					strings.Contains(entry.Name(), ".so.") {
					ps.addFinding(Finding{
						Type:        "SUSPICIOUS_SHARED_LIB",
						Severity:    "HIGH",
						Path:        filepath.Join(dir, entry.Name()),
						Description: fmt.Sprintf("Shared library in suspicious location: %s", entry.Name()),
						Details:     "May be used for LD_PRELOAD injection",
					})
				}
			}
		}
	}
}

// ScanPrivilegeEscalation checks for privilege escalation indicators
func (ps *PersistenceScanner) ScanPrivilegeEscalation() {
	fmt.Printf("%s[PERSIST]%s Checking for privilege escalation...\n", colorCyan, colorReset)

	currentUser, err := user.Current()
	if err != nil {
		return
	}

	// Check sudoers.d for user-specific files (fast, just reads directory)
	sudoersDir := "/etc/sudoers.d"
	if entries, err := os.ReadDir(sudoersDir); err == nil {
		for _, entry := range entries {
			if strings.Contains(strings.ToLower(entry.Name()), currentUser.Username) {
				ps.addFinding(Finding{
					Type:        "SUDOERS_ENTRY",
					Severity:    "HIGH",
					Path:        filepath.Join(sudoersDir, entry.Name()),
					Description: fmt.Sprintf("User-specific sudoers file found: %s", entry.Name()),
					Details:     "Verify this file is legitimate",
				})
			}
		}
	}

	fmt.Printf("%s[PERSIST]%s Privilege escalation check complete\n", colorGreen, colorReset)
}

// ScanRecentlyModifiedBinaries checks for recently modified executables
func (ps *PersistenceScanner) ScanRecentlyModifiedBinaries() {
	fmt.Printf("%s[PERSIST]%s Checking for recently modified binaries...\n", colorCyan, colorReset)

	// Directories where user binaries might be modified
	binDirs := []string{
		filepath.Join(ps.homeDir, ".local", "bin"),
		filepath.Join(ps.homeDir, "bin"),
		filepath.Join(ps.homeDir, ".npm-global", "bin"),
		"/usr/local/bin",
	}

	threshold := 7 * 24 * time.Hour // 7 days

	for _, binDir := range binDirs {
		entries, err := os.ReadDir(binDir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			path := filepath.Join(binDir, entry.Name())
			info, err := entry.Info()
			if err != nil {
				continue
			}

			// Check if modified recently
			if time.Since(info.ModTime()) < threshold {
				// Check if executable
				if info.Mode()&0111 != 0 {
					// Calculate a quick hash for reference
					content, err := os.ReadFile(path)
					if err != nil {
						continue
					}
					hash := sha512.Sum512(content)
					hashStr := hex.EncodeToString(hash[:8]) // First 8 bytes

					ps.addFinding(Finding{
						Type:        "RECENTLY_MODIFIED_BIN",
						Severity:    "MEDIUM",
						Path:        path,
						Description: fmt.Sprintf("Binary modified within last 7 days: %s", entry.Name()),
						Details:     fmt.Sprintf("Modified: %s, Hash: %s...", info.ModTime().Format("2006-01-02"), hashStr),
					})
				}
			}
		}
	}
}

// Run performs all persistence checks
func (ps *PersistenceScanner) Run() []Finding {
	fmt.Printf("\n%s%s╔══════════════════════════════════════════════════════════════════╗%s\n", colorBold, colorPurple, colorReset)
	fmt.Printf("%s%s║  🔒 PERSISTENCE & PRIVILEGE ESCALATION SCANNER                    ║%s\n", colorBold, colorPurple, colorReset)
	fmt.Printf("%s%s║  Deep scan for backdoors, hijacks, and persistence mechanisms     ║%s\n", colorBold, colorPurple, colorReset)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════╝%s\n", colorBold, colorPurple, colorReset)

	var wg sync.WaitGroup

	// First wave: Quick checks
	wg.Add(7)
	go func() { defer wg.Done(); ps.ScanGitHooks() }()
	go func() { defer wg.Done(); ps.ScanSSHAuthorizedKeys() }()
	go func() { defer wg.Done(); ps.ScanCronJobs() }()
	go func() { defer wg.Done(); ps.ScanShellConfigs() }()
	go func() { defer wg.Done(); ps.ScanGlobalNpmPackages() }()
	go func() { defer wg.Done(); ps.ScanListeningPorts() }()
	go func() { defer wg.Done(); ps.ScanPATHHijacking() }()
	wg.Wait()

	// Second wave: Deep checks
	wg.Add(7)
	go func() { defer wg.Done(); ps.ScanPackageLockIntegrity() }()
	go func() { defer wg.Done(); ps.ScanVSCodeExtensions() }()
	go func() { defer wg.Done(); ps.ScanBrowserExtensions() }()
	go func() { defer wg.Done(); ps.ScanDockerContainers() }()
	go func() { defer wg.Done(); ps.ScanLDPreload() }()
	go func() { defer wg.Done(); ps.ScanPrivilegeEscalation() }()
	go func() { defer wg.Done(); ps.ScanRecentlyModifiedBinaries() }()

	wg.Wait()

	if len(ps.findings) > 0 {
		fmt.Printf("\n%s%s[PERSISTENCE FINDINGS] (%d detected)%s\n", colorBold, colorRed, len(ps.findings), colorReset)
		fmt.Println(strings.Repeat("─", 70))

		for _, f := range ps.findings {
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
		fmt.Printf("%s[PERSIST]%s No persistence mechanisms detected\n", colorGreen, colorReset)
	}

	return ps.findings
}
