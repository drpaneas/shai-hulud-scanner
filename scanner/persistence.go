package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// PersistenceScanner checks for Shai-Hulud v2 specific persistence mechanisms
type PersistenceScanner struct {
	findings      []Finding
	findingsMutex sync.Mutex
	homeDir       string
}

// Shai-Hulud specific patterns in git hooks
var shaiHuludHookPatterns = [][]byte{
	[]byte("bun.sh"),
	[]byte("bun_environment"),
	[]byte("setup_bun"),
	[]byte("trufflehog"),
	[]byte("SHA1HULUD"),
	[]byte("Sha1-Hulud"),
	[]byte("shai-hulud"),
	[]byte(".truffler-cache"),
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

// ScanGitHooks checks git hooks for Shai-Hulud malware patterns
func (ps *PersistenceScanner) ScanGitHooks() {
	fmt.Printf("%s[PERSIST]%s Scanning git hooks for Shai-Hulud patterns...\n", colorCyan, colorReset)

	dangerousHooks := []string{
		"pre-commit", "post-commit", "pre-push", "post-checkout",
		"post-merge", "pre-rebase", "post-rewrite", "prepare-commit-msg",
		"commit-msg", "pre-receive", "post-receive", "update",
		"pre-install", "post-install",
	}

	searchPaths := []string{
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
			if err != nil {
				return nil
			}

			// Limit depth
			rel, _ := filepath.Rel(searchPath, path)
			if strings.Count(rel, string(filepath.Separator)) > 4 {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			if info.IsDir() {
				if info.Name() == "node_modules" || info.Name() == "vendor" {
					return filepath.SkipDir
				}
				if info.Name() == ".git" {
					hooksDir := filepath.Join(path, "hooks")
					ps.checkHooksDir(hooksDir, dangerousHooks)
					checked++
					if checked > 200 {
						return filepath.SkipAll
					}
					return filepath.SkipDir
				}
				return nil
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

		// Check for Shai-Hulud specific patterns only
		var suspicious []string
		for _, pattern := range shaiHuludHookPatterns {
			if bytes.Contains(content, pattern) {
				suspicious = append(suspicious, string(pattern))
			}
		}

		if len(suspicious) > 0 {
			ps.addFinding(Finding{
				Type:        "SHAI_HULUD_GIT_HOOK",
				Severity:    "CRITICAL",
				Path:        hookPath,
				Description: fmt.Sprintf("Git hook '%s' contains Shai-Hulud malware patterns", hookName),
				Details:     fmt.Sprintf("Found: %s", strings.Join(suspicious, ", ")),
			})
		}
	}
}

// ScanGlobalNpmPackages checks for Shai-Hulud infected global packages
func (ps *PersistenceScanner) ScanGlobalNpmPackages() {
	fmt.Printf("%s[PERSIST]%s Checking global npm packages for Shai-Hulud...\n", colorCyan, colorReset)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "npm", "ls", "-g", "--depth=0", "--json")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	// Known Shai-Hulud related packages
	maliciousPackages := []string{
		"bun_environment",
		"setup_bun",
		"trufflehog",
	}

	outputStr := string(output)
	for _, pkg := range maliciousPackages {
		if strings.Contains(outputStr, pkg) {
			ps.addFinding(Finding{
				Type:        "SHAI_HULUD_GLOBAL_PACKAGE",
				Severity:    "CRITICAL",
				Path:        "npm global",
				Description: fmt.Sprintf("Shai-Hulud related global package: %s", pkg),
				Details:     "Run: npm ls -g to investigate",
			})
		}
	}
}

// ScanTrufflerCache checks for .truffler-cache directory in common locations
func (ps *PersistenceScanner) ScanTrufflerCache() {
	fmt.Printf("%s[PERSIST]%s Checking for .truffler-cache directories...\n", colorCyan, colorReset)

	// Check common locations for .truffler-cache
	locations := []string{
		filepath.Join(ps.homeDir, ".truffler-cache"),
		"/tmp/.truffler-cache",
		"/var/tmp/.truffler-cache",
	}

	for _, loc := range locations {
		if info, err := os.Stat(loc); err == nil && info.IsDir() {
			ps.addFinding(Finding{
				Type:        "SHAI_HULUD_CACHE",
				Severity:    "CRITICAL",
				Path:        loc,
				Description: "Found .truffler-cache directory - Shai-Hulud malware storage",
				Details:     "This directory is used by the malware to store Trufflehog binary",
			})
		}
	}
}

// ScanGitHubRunners checks for Shai-Hulud self-hosted runners
func (ps *PersistenceScanner) ScanGitHubRunners() {
	fmt.Printf("%s[PERSIST]%s Checking for Shai-Hulud GitHub runners...\n", colorCyan, colorReset)

	// Check for runner directories
	runnerPaths := []string{
		filepath.Join(ps.homeDir, "actions-runner"),
		filepath.Join(ps.homeDir, ".actions-runner"),
		"/opt/actions-runner",
		"/home/runner",
	}

	for _, runnerPath := range runnerPaths {
		configPath := filepath.Join(runnerPath, ".runner")
		content, err := os.ReadFile(configPath)
		if err != nil {
			continue
		}

		// Check for Shai-Hulud runner name
		if bytes.Contains(content, []byte("SHA1HULUD")) ||
			bytes.Contains(content, []byte("Sha1-Hulud")) ||
			bytes.Contains(content, []byte("shai-hulud")) {
			ps.addFinding(Finding{
				Type:        "SHAI_HULUD_RUNNER",
				Severity:    "CRITICAL",
				Path:        configPath,
				Description: "Found Shai-Hulud self-hosted GitHub runner",
				Details:     "This runner was likely registered by the malware for backdoor access",
			})
		}
	}
}

// ScanPackageLockIntegrity checks package-lock.json for Shai-Hulud patterns
func (ps *PersistenceScanner) ScanPackageLockIntegrity() {
	fmt.Printf("%s[PERSIST]%s Checking package-lock.json for Shai-Hulud patterns...\n", colorCyan, colorReset)

	// Shai-Hulud specific patterns
	maliciousPatterns := []string{
		"bun_environment",
		"setup_bun",
		"trufflehog",
		".truffler-cache",
	}

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

			rel, _ := filepath.Rel(searchPath, path)
			if strings.Count(rel, string(filepath.Separator)) > 3 {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

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

	contentStr := string(content)
	for _, pattern := range maliciousPatterns {
		if strings.Contains(contentStr, pattern) {
			ps.addFinding(Finding{
				Type:        "SHAI_HULUD_LOCKFILE",
				Severity:    "CRITICAL",
				Path:        path,
				Description: fmt.Sprintf("package-lock.json contains Shai-Hulud pattern: %s", pattern),
				Details:     "This lockfile may have been tampered with by the malware",
			})
		}
	}

	// Check for suspicious postinstall scripts referencing malware
	var lockFile map[string]interface{}
	if err := json.Unmarshal(content, &lockFile); err != nil {
		return
	}

	if packages, ok := lockFile["packages"].(map[string]interface{}); ok {
		for pkgPath, pkgData := range packages {
			if pkg, ok := pkgData.(map[string]interface{}); ok {
				if scripts, ok := pkg["scripts"].(map[string]interface{}); ok {
					for scriptName, scriptCmd := range scripts {
						if cmd, ok := scriptCmd.(string); ok {
							if strings.Contains(cmd, "setup_bun") || strings.Contains(cmd, "bun_environment") {
								ps.addFinding(Finding{
									Type:        "SHAI_HULUD_SCRIPT",
									Severity:    "CRITICAL",
									Path:        path,
									Description: fmt.Sprintf("Package '%s' has Shai-Hulud %s script", pkgPath, scriptName),
									Details:     fmt.Sprintf("Script: %s", truncate(cmd, 80)),
								})
							}
						}
					}
				}
			}
		}
	}
}

// Run performs all Shai-Hulud specific persistence checks
func (ps *PersistenceScanner) Run() []Finding {
	fmt.Printf("\n%s%s╔══════════════════════════════════════════════════════════════════╗%s\n", colorBold, colorPurple, colorReset)
	fmt.Printf("%s%s║  🐛 SHAI-HULUD v2 PERSISTENCE SCANNER                             ║%s\n", colorBold, colorPurple, colorReset)
	fmt.Printf("%s%s║  Checking for malware persistence mechanisms                      ║%s\n", colorBold, colorPurple, colorReset)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════╝%s\n", colorBold, colorPurple, colorReset)

	var wg sync.WaitGroup

	wg.Add(5)
	go func() { defer wg.Done(); ps.ScanGitHooks() }()
	go func() { defer wg.Done(); ps.ScanGlobalNpmPackages() }()
	go func() { defer wg.Done(); ps.ScanTrufflerCache() }()
	go func() { defer wg.Done(); ps.ScanGitHubRunners() }()
	go func() { defer wg.Done(); ps.ScanPackageLockIntegrity() }()

	wg.Wait()

	if len(ps.findings) > 0 {
		fmt.Printf("\n%s%s[SHAI-HULUD PERSISTENCE FINDINGS] (%d detected)%s\n", colorBold, colorRed, len(ps.findings), colorReset)
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
		fmt.Printf("%s[PERSIST]%s No Shai-Hulud persistence mechanisms detected\n", colorGreen, colorReset)
	}

	return ps.findings
}
