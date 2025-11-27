package scanner

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/karrick/godirwalk"
)

const WizIOCPackagesURL = "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv"

// Pre-compiled byte patterns for ultra-fast matching
var (
	bunEnvPattern     = []byte("bun_environment.js")
	bunInstallPattern = []byte("bun.sh/install")
	runExecPattern    = []byte("runExecutable")
	bunPathPattern    = []byte("bunPath")
	downloadSetupBun  = []byte("downloadAndSetupBun")
	selfHostedPattern = []byte("self-hosted")
	discussionPattern = []byte("discussion")
	discussionBody    = []byte("github.event.discussion.body")
	sha1HuludPattern  = []byte("SHA1HULUD")
	sha1HuludPattern2 = []byte("Sha1-Hulud")
	setupBunJSPattern = []byte("setup_bun.js")
)

// Directories to skip
var skipDirs = map[string]struct{}{
	".git": {}, ".svn": {}, ".hg": {}, "vendor": {}, "__pycache__": {},
	".cache": {}, "dist": {}, "build": {}, ".next": {}, ".venv": {},
	"venv": {}, ".tox": {}, ".pytest_cache": {}, ".mypy_cache": {},
	"coverage": {}, ".nyc_output": {}, ".parcel-cache": {}, ".turbo": {},
	".vercel": {}, ".netlify": {}, "__MACOSX": {}, ".Spotlight-V100": {},
	".fseventsd": {}, ".Trashes": {}, ".DocumentRevisions-V100": {},
	".TemporaryItems": {}, "Library": {}, ".Trash": {}, "Applications": {},
	".npm": {}, ".nvm": {}, ".cargo": {}, ".rustup": {}, ".gradle": {},
	".m2": {}, ".android": {}, ".cocoapods": {}, "Pods": {}, ".docker": {},
	"Movies": {}, "Music": {}, "Photos": {}, "Pictures": {}, ".local": {},
}

// Finding represents a detected indicator of compromise
type Finding struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Path        string `json:"path"`
	Description string `json:"description"`
	Details     string `json:"details,omitempty"`
}

// DiskScanner handles filesystem scanning
type DiskScanner struct {
	findings      []Finding
	findingsMutex sync.Mutex
	scannedFiles  atomic.Int64
	scannedDirs   atomic.Int64
	infectedPkgs  map[string]map[string]bool
	workers       int
	offline       bool
	bufferPool    sync.Pool
}

// PackageJSON represents package.json structure
type PackageJSON struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Scripts map[string]string `json:"scripts"`
}

// NewDiskScanner creates a new disk scanner
func NewDiskScanner(workers int, offline bool) *DiskScanner {
	return &DiskScanner{
		findings:     make([]Finding, 0, 100),
		infectedPkgs: make(map[string]map[string]bool),
		workers:      workers,
		offline:      offline,
		bufferPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 64*1024)
				return &buf
			},
		},
	}
}

// FindingCount returns the number of findings
func (s *DiskScanner) FindingCount() int {
	return len(s.findings)
}

// fetchInfectedPackages downloads the IOC list
func (s *DiskScanner) fetchInfectedPackages() error {
	fmt.Printf("%s[INFO]%s Fetching latest IOC list from Wiz Research...\n", colorBlue, colorReset)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(WizIOCPackagesURL)
	if err != nil {
		return fmt.Errorf("failed to fetch IOC list: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch IOC list: HTTP %d", resp.StatusCode)
	}

	return s.parseIOCCSV(resp.Body)
}

func (s *DiskScanner) parseIOCCSV(reader io.Reader) error {
	csvReader := csv.NewReader(reader)
	header, err := csvReader.Read()
	if err != nil {
		return fmt.Errorf("failed to read CSV header: %w", err)
	}

	if len(header) < 2 || header[0] != "Package" || header[1] != "Version" {
		return fmt.Errorf("unexpected CSV format")
	}

	versionRegex := regexp.MustCompile(`=\s*(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?)`)

	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(record) < 1 {
			continue
		}

		packageName := strings.TrimSpace(record[0])
		if packageName == "" {
			continue
		}

		if s.infectedPkgs[packageName] == nil {
			s.infectedPkgs[packageName] = make(map[string]bool)
		}

		if len(record) >= 2 && record[1] != "" {
			for _, match := range versionRegex.FindAllStringSubmatch(record[1], -1) {
				if len(match) >= 2 {
					s.infectedPkgs[packageName][strings.TrimSpace(match[1])] = true
				}
			}
		}
	}

	fmt.Printf("%s[INFO]%s Loaded %d infected packages from IOC database\n", colorGreen, colorReset, len(s.infectedPkgs))
	return nil
}

func (s *DiskScanner) loadOfflinePackages() {
	fmt.Printf("%s[WARN]%s Running in offline mode with limited package list\n", colorYellow, colorReset)

	// Critical packages from Shai-Hulud 2.0 "Second Coming" campaign
	// Sources: Wiz, Datadog, Tenable, PostHog, Postman, Zapier incident reports
	criticalPackages := map[string][]string{
		// Postman - 17 packages, 51 versions affected
		"@postman/tunnel-agent": {"0.6.5", "0.6.6", "0.6.7", "2.0.19", "2.0.20", "2.0.21"},

		// PostHog - confirmed affected versions
		"posthog-node": {"4.3.2", "4.3.3", "4.18.1", "5.11.3", "5.13.3"},
		"posthog-js":   {"1.205.1", "1.205.2", "1.297.3"},

		// Zapier - confirmed affected versions
		"zapier-platform-cli":  {"18.0.2", "18.0.3", "18.0.4"},
		"zapier-platform-core": {"18.0.2", "18.0.3", "18.0.4"},
		"zapier-sdk":           {"18.0.2", "18.0.3", "18.0.4"},
		"babel-preset-zapier":  {"1.0.0", "1.0.1"},

		// AsyncAPI - patient zero
		"@asyncapi/cli":                   {"6.8.2", "6.8.3", "6.9.1", "6.10.1"},
		"@asyncapi/specs":                 {"6.8.2", "6.8.3", "6.9.1", "6.10.1"},
		"@asyncapi/openapi-schema-parser": {"3.0.25", "3.0.26"},

		// ENS Domains
		"@ensdomains/hardhat-chai-matchers-viem": {"1.0.0", "1.0.1"},
		"ethereum-ens": {"0.8.0", "0.8.1"},

		// Other known affected
		"kill-port":                {"2.0.2", "2.0.3"},
		"shell-exec":               {"1.1.3", "1.1.4"},
		"@browserbasehq/stagehand": {"3.0.4"},
	}

	for pkg, versions := range criticalPackages {
		s.infectedPkgs[pkg] = make(map[string]bool)
		for _, v := range versions {
			s.infectedPkgs[pkg][v] = true
		}
	}

	fmt.Printf("%s[INFO]%s Loaded %d critical packages for offline scanning\n", colorBlue, colorReset, len(s.infectedPkgs))
}

func (s *DiskScanner) addFinding(finding Finding) {
	s.findingsMutex.Lock()
	s.findings = append(s.findings, finding)
	s.findingsMutex.Unlock()
}

// Scan performs the filesystem scan
func (s *DiskScanner) Scan(rootPath string) {
	fmt.Printf("\n%s%s╔══════════════════════════════════════════════════════════════════╗%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s║  🐛 SHAI-HULUD v2 MALWARE SCANNER (GODIRWALK TURBO)               ║%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s║  Ultra-fast parallel disk scanning with godirwalk                 ║%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s║  Sources: GitLab, Wiz Research, Node.js Security                  ║%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════╝%s\n", colorBold, colorCyan, colorReset)

	if s.offline {
		s.loadOfflinePackages()
	} else {
		if err := s.fetchInfectedPackages(); err != nil {
			fmt.Printf("%s[WARN]%s Failed to fetch IOC list: %v\n", colorYellow, colorReset, err)
			s.loadOfflinePackages()
		}
	}

	fmt.Printf("\n%s[INFO]%s Scanning path: %s\n", colorBlue, colorReset, rootPath)
	fmt.Printf("%s[INFO]%s Using %d worker goroutines\n", colorBlue, colorReset, s.workers)
	fmt.Printf("%s[INFO]%s Tracking %d infected packages\n\n", colorBlue, colorReset, len(s.infectedPkgs))

	startTime := time.Now()

	fileChan := make(chan string, 1000000)

	var wg sync.WaitGroup
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileChan {
				s.processFile(path)
			}
		}()
	}

	done := make(chan bool)
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				elapsed := time.Since(startTime).Seconds()
				if elapsed > 0 {
					filesPerSec := float64(s.scannedFiles.Load()) / elapsed
					fmt.Printf("\r%s[SCANNING]%s Files: %d | Dirs: %d | Findings: %d | Speed: %.0f files/sec    ",
						colorYellow, colorReset,
						s.scannedFiles.Load(),
						s.scannedDirs.Load(),
						len(s.findings),
						filesPerSec)
				}
			}
		}
	}()

	_ = godirwalk.Walk(rootPath, &godirwalk.Options{
		Unsorted:            true,
		FollowSymbolicLinks: false,
		Callback: func(path string, de *godirwalk.Dirent) error {
			name := de.Name()

			if de.IsDir() {
				s.scannedDirs.Add(1)

				if name == ".truffler-cache" {
					s.addFinding(Finding{
						Type:        "MALICIOUS_DIRECTORY",
						Severity:    "CRITICAL",
						Path:        path,
						Description: "Found .truffler-cache directory - Shai-Hulud malware indicator",
						Details:     "Hidden directory created by malware for Trufflehog binary storage.",
					})
				}

				if _, skip := skipDirs[name]; skip {
					return godirwalk.SkipThis
				}
				if len(name) > 0 && name[0] == '.' && name != ".github" && name != ".truffler-cache" {
					return godirwalk.SkipThis
				}
				return nil
			}

			select {
			case fileChan <- path:
			default:
				s.processFile(path)
			}
			return nil
		},
		ErrorCallback: func(path string, err error) godirwalk.ErrorAction {
			return godirwalk.SkipNode
		},
	})

	close(fileChan)
	wg.Wait()
	done <- true

	elapsed := time.Since(startTime)
	filesPerSec := float64(s.scannedFiles.Load()) / elapsed.Seconds()

	fmt.Printf("\r%s[COMPLETE]%s Scanned %d files in %d directories (%.2fs @ %.0f files/sec)%s\n\n",
		colorGreen, colorReset,
		s.scannedFiles.Load(),
		s.scannedDirs.Load(),
		elapsed.Seconds(),
		filesPerSec,
		strings.Repeat(" ", 20))

	s.printResults()
}

func (s *DiskScanner) processFile(path string) {
	s.scannedFiles.Add(1)
	name := filepath.Base(path)

	switch name {
	case "bun_environment.js":
		s.addFinding(Finding{
			Type:        "MALICIOUS_FILE",
			Severity:    "CRITICAL",
			Path:        path,
			Description: "Found bun_environment.js - Main Shai-Hulud malware payload",
			Details:     "Obfuscated malware that steals credentials and propagates.",
		})
		return

	case "setup_bun.js":
		s.checkSetupBunFile(path)
		return

	case "verify.js":
		// Another variant of malware loader
		s.checkVerifyJSFile(path)
		return

	case "trufflehog", "trufflehog.exe":
		if strings.Contains(path, ".truffler-cache") {
			s.addFinding(Finding{
				Type:        "MALICIOUS_FILE",
				Severity:    "CRITICAL",
				Path:        path,
				Description: "Found Trufflehog binary in .truffler-cache directory",
				Details:     "Malware uses Trufflehog to scan for secrets.",
			})
		}
		return

	case "package.json":
		if strings.Contains(path, "node_modules") {
			s.checkForInfectedPackage(path)
		} else {
			s.checkPackageJSON(path)
		}
		return

	case "discussion.yaml", "shaihuludworkflow.yml", "shai-hulud-workflow.yml":
		if strings.Contains(path, ".github"+string(filepath.Separator)+"workflows") {
			s.checkMaliciousWorkflow(path, name)
		}
		return

	case "cloud.json", "contents.json", "environment.json", "truffleSecrets.json":
		// These exfiltration files can appear anywhere
		s.addFinding(Finding{
			Type:        "EXFILTRATION_DATA",
			Severity:    "CRITICAL",
			Path:        path,
			Description: fmt.Sprintf("Found %s - Shai-Hulud exfiltration data file", name),
			Details:     "Contains stolen credentials harvested by the malware.",
		})
		return
	}

	// Check any .yaml/.yml file in .github/workflows for Shai-Hulud patterns
	if (strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")) &&
		strings.Contains(path, ".github"+string(filepath.Separator)+"workflows") {
		s.checkWorkflowForShaiHulud(path)
	}
}

func (s *DiskScanner) checkSetupBunFile(path string) {
	bufPtr := s.bufferPool.Get().(*[]byte)
	defer s.bufferPool.Put(bufPtr)

	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()

	n, _ := file.Read(*bufPtr)
	content := (*bufPtr)[:n]

	var details []string
	if bytes.Contains(content, bunEnvPattern) {
		details = append(details, "References bun_environment.js payload")
	}
	if bytes.Contains(content, bunInstallPattern) {
		details = append(details, "Contains Bun installation command")
	}
	if bytes.Contains(content, runExecPattern) && bytes.Contains(content, bunPathPattern) {
		details = append(details, "Contains malware execution pattern")
	}
	if bytes.Contains(content, downloadSetupBun) {
		details = append(details, "Contains malware loader function")
	}

	if len(details) > 0 {
		s.addFinding(Finding{
			Type:        "MALICIOUS_FILE",
			Severity:    "CRITICAL",
			Path:        path,
			Description: "Found malicious setup_bun.js loader script",
			Details:     strings.Join(details, "; "),
		})
	}
}

func (s *DiskScanner) checkVerifyJSFile(path string) {
	bufPtr := s.bufferPool.Get().(*[]byte)
	defer s.bufferPool.Put(bufPtr)

	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()

	n, _ := file.Read(*bufPtr)
	content := (*bufPtr)[:n]

	// Check for Shai-Hulud specific patterns in verify.js
	malwarePatterns := [][]byte{
		[]byte("bun_environment"),
		[]byte("setup_bun"),
		[]byte("trufflehog"),
		[]byte("bun.sh"),
		[]byte("downloadAndSetupBun"),
		[]byte("SHA1HULUD"),
		[]byte("Sha1-Hulud"),
	}

	for _, pattern := range malwarePatterns {
		if bytes.Contains(content, pattern) {
			s.addFinding(Finding{
				Type:        "MALICIOUS_FILE",
				Severity:    "CRITICAL",
				Path:        path,
				Description: "Found verify.js with Shai-Hulud malware patterns",
				Details:     fmt.Sprintf("Contains: %s", string(pattern)),
			})
			return
		}
	}
}

func (s *DiskScanner) checkMaliciousWorkflow(path string, name string) {
	bufPtr := s.bufferPool.Get().(*[]byte)
	defer s.bufferPool.Put(bufPtr)

	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()

	n, _ := file.Read(*bufPtr)
	content := (*bufPtr)[:n]

	var details []string

	// Check for self-hosted runner (backdoor indicator)
	if bytes.Contains(content, selfHostedPattern) {
		details = append(details, "Uses self-hosted runner")
	}

	// Check for discussion trigger (injection vector)
	if bytes.Contains(content, discussionPattern) {
		details = append(details, "Triggered by discussions")
	}

	// Check for command injection via discussion body
	if bytes.Contains(content, discussionBody) {
		details = append(details, "Contains command injection via discussion.body")
	}

	// Check for Shai-Hulud identifiers
	if bytes.Contains(content, sha1HuludPattern) || bytes.Contains(content, sha1HuludPattern2) {
		details = append(details, "Contains Shai-Hulud identifier")
	}

	// Check for "The Second Coming" or "The Continued Coming"
	if bytes.Contains(content, []byte("The Second Coming")) || bytes.Contains(content, []byte("The Continued Coming")) {
		details = append(details, "Contains Shai-Hulud campaign marker")
	}

	if len(details) > 0 || name == "shaihuludworkflow.yml" || name == "shai-hulud-workflow.yml" {
		s.addFinding(Finding{
			Type:        "BACKDOOR_WORKFLOW",
			Severity:    "CRITICAL",
			Path:        path,
			Description: fmt.Sprintf("Found malicious %s GitHub workflow backdoor", name),
			Details:     strings.Join(details, "; "),
		})
	}
}

func (s *DiskScanner) checkWorkflowForShaiHulud(path string) {
	bufPtr := s.bufferPool.Get().(*[]byte)
	defer s.bufferPool.Put(bufPtr)

	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()

	n, _ := file.Read(*bufPtr)
	content := (*bufPtr)[:n]

	// Only flag if we find Shai-Hulud specific patterns
	shaiHuludPatterns := [][]byte{
		sha1HuludPattern,
		sha1HuludPattern2,
		[]byte("The Second Coming"),
		[]byte("The Continued Coming"),
		[]byte("bun_environment"),
		[]byte("setup_bun"),
		[]byte("trufflehog"),
		[]byte(".truffler-cache"),
	}

	for _, pattern := range shaiHuludPatterns {
		if bytes.Contains(content, pattern) {
			s.addFinding(Finding{
				Type:        "BACKDOOR_WORKFLOW",
				Severity:    "CRITICAL",
				Path:        path,
				Description: "GitHub workflow contains Shai-Hulud malware pattern",
				Details:     fmt.Sprintf("Found: %s", string(pattern)),
			})
			return
		}
	}

	// Check for suspicious self-hosted + discussion combination
	if bytes.Contains(content, selfHostedPattern) && bytes.Contains(content, discussionBody) {
		s.addFinding(Finding{
			Type:        "SUSPICIOUS_WORKFLOW",
			Severity:    "HIGH",
			Path:        path,
			Description: "GitHub workflow with self-hosted runner and discussion injection",
			Details:     "This pattern matches the Shai-Hulud attack vector",
		})
	}
}

func (s *DiskScanner) checkPackageJSON(path string) {
	bufPtr := s.bufferPool.Get().(*[]byte)
	defer s.bufferPool.Put(bufPtr)

	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()

	n, _ := file.Read(*bufPtr)
	content := (*bufPtr)[:n]

	var pkg PackageJSON
	if err := json.Unmarshal(content, &pkg); err != nil {
		return
	}

	// Check install scripts for Shai-Hulud patterns
	suspiciousScriptPatterns := []string{
		"setup_bun.js",
		"bun_environment",
		"verify.js",
		"bun run",
		"bun.sh",
		"trufflehog",
	}

	// More aggressive patterns that indicate malware loader
	malwareLoaderPatterns := []string{
		"curl",
		"wget",
		"| bash",
		"| sh",
		"eval",
	}

	for _, scriptType := range []string{"preinstall", "postinstall", "install", "prepare"} {
		if script, ok := pkg.Scripts[scriptType]; ok {
			// Check for direct Shai-Hulud indicators
			for _, pattern := range suspiciousScriptPatterns {
				if strings.Contains(script, pattern) {
					s.addFinding(Finding{
						Type:        "MALICIOUS_SCRIPT",
						Severity:    "CRITICAL",
						Path:        path,
						Description: fmt.Sprintf("Package '%s' has Shai-Hulud %s script", pkg.Name, scriptType),
						Details:     fmt.Sprintf("%s: %s", scriptType, script),
					})
					return
				}
			}

			// Check for suspicious loader patterns (might download malware)
			for _, pattern := range malwareLoaderPatterns {
				if strings.Contains(script, pattern) {
					s.addFinding(Finding{
						Type:        "SUSPICIOUS_SCRIPT",
						Severity:    "HIGH",
						Path:        path,
						Description: fmt.Sprintf("Package '%s' has suspicious %s script with '%s'", pkg.Name, scriptType, pattern),
						Details:     fmt.Sprintf("%s: %s", scriptType, script),
					})
					return
				}
			}
		}
	}

	// Check if package has dependencies on known infected packages
	s.checkDependenciesForInfected(path, content)
}

func (s *DiskScanner) checkDependenciesForInfected(path string, content []byte) {
	// Parse dependencies
	var pkgFull struct {
		Name            string            `json:"name"`
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.Unmarshal(content, &pkgFull); err != nil {
		return
	}

	// Check dependencies against IOC list
	allDeps := make(map[string]string)
	for k, v := range pkgFull.Dependencies {
		allDeps[k] = v
	}
	for k, v := range pkgFull.DevDependencies {
		allDeps[k] = v
	}

	for depName := range allDeps {
		if _, infected := s.infectedPkgs[depName]; infected {
			s.addFinding(Finding{
				Type:        "INFECTED_DEPENDENCY",
				Severity:    "HIGH",
				Path:        path,
				Description: fmt.Sprintf("Package '%s' depends on potentially infected package: %s", pkgFull.Name, depName),
				Details:     "Run: npm ls " + depName + " to check installed version",
			})
		}
	}
}

func (s *DiskScanner) checkForInfectedPackage(path string) {
	bufPtr := s.bufferPool.Get().(*[]byte)
	defer s.bufferPool.Put(bufPtr)

	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()

	n, _ := file.Read(*bufPtr)
	content := (*bufPtr)[:n]

	var pkg PackageJSON
	if err := json.Unmarshal(content, &pkg); err != nil {
		return
	}

	if versions, exists := s.infectedPkgs[pkg.Name]; exists {
		if len(versions) > 0 {
			if versions[pkg.Version] {
				s.addFinding(Finding{
					Type:        "INFECTED_PACKAGE",
					Severity:    "CRITICAL",
					Path:        path,
					Description: fmt.Sprintf("Found infected package: %s@%s", pkg.Name, pkg.Version),
					Details:     "This package version is compromised by Shai-Hulud v2.",
				})
			}
		} else {
			s.addFinding(Finding{
				Type:        "SUSPICIOUS_PACKAGE",
				Severity:    "HIGH",
				Path:        path,
				Description: fmt.Sprintf("Potentially infected package: %s@%s", pkg.Name, pkg.Version),
				Details:     "Package in IOC list but version-specific data unavailable.",
			})
		}
	}

	if bytes.Contains(content, setupBunJSPattern) || bytes.Contains(content, bunEnvPattern) {
		for _, scriptType := range []string{"preinstall", "postinstall", "install"} {
			if script, ok := pkg.Scripts[scriptType]; ok {
				if strings.Contains(script, "setup_bun.js") || strings.Contains(script, "bun_environment") {
					s.addFinding(Finding{
						Type:        "MALICIOUS_SCRIPT",
						Severity:    "CRITICAL",
						Path:        path,
						Description: fmt.Sprintf("Package '%s@%s' has malicious %s script", pkg.Name, pkg.Version, scriptType),
						Details:     fmt.Sprintf("%s: %s", scriptType, script),
					})
				}
			}
		}
	}
}

func (s *DiskScanner) printResults() {
	if len(s.findings) == 0 {
		fmt.Printf("%s%s╔══════════════════════════════════════════════════════════════════╗%s\n", colorBold, colorGreen, colorReset)
		fmt.Printf("%s%s║  ✅ NO INFECTIONS DETECTED                                        ║%s\n", colorBold, colorGreen, colorReset)
		fmt.Printf("%s%s║  Your system appears to be clean of Shai-Hulud v2 indicators      ║%s\n", colorBold, colorGreen, colorReset)
		fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════╝%s\n", colorBold, colorGreen, colorReset)
		s.printPreventionTips()
		return
	}

	fmt.Printf("%s%s╔══════════════════════════════════════════════════════════════════╗%s\n", colorBold, colorRed, colorReset)
	fmt.Printf("%s%s║  ⚠️  INFECTIONS DETECTED: %-3d                                     ║%s\n", colorBold, colorRed, len(s.findings), colorReset)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════╝%s\n", colorBold, colorRed, colorReset)

	byType := make(map[string][]Finding)
	for _, f := range s.findings {
		byType[f.Type] = append(byType[f.Type], f)
	}

	for findingType, findings := range byType {
		fmt.Printf("\n%s%s[%s] (%d findings)%s\n", colorBold, colorPurple, findingType, len(findings), colorReset)
		fmt.Println(strings.Repeat("─", 70))

		for _, f := range findings {
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
	}

	s.printRemediationSteps()
}

func (s *DiskScanner) printRemediationSteps() {
	fmt.Printf("\n%s%s╔══════════════════════════════════════════════════════════════════╗%s\n", colorBold, colorYellow, colorReset)
	fmt.Printf("%s%s║  🚨 RECOMMENDED ACTIONS                                           ║%s\n", colorBold, colorYellow, colorReset)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════╝%s\n", colorBold, colorYellow, colorReset)
	fmt.Println()
	fmt.Printf("%s⚠️  WARNING: DO NOT simply delete the malware files!%s\n", colorRed, colorReset)
	fmt.Println("   This may trigger the 'dead man's switch' destructive payload!")
	fmt.Println()
	fmt.Println("1. 🔐 IMMEDIATELY rotate ALL credentials")
	fmt.Println("2. 🔍 Check for self-hosted GitHub runners named 'SHA1HULUD'")
	fmt.Println("3. 📦 Clean and reinstall packages with --ignore-scripts")
	fmt.Println()
	s.printPreventionTips()
}

func (s *DiskScanner) printPreventionTips() {
	fmt.Printf("\n%s%s╔══════════════════════════════════════════════════════════════════╗%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s║  🛡️  PREVENTION: USING --ignore-scripts                           ║%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════╝%s\n", colorBold, colorCyan, colorReset)
	fmt.Println()
	fmt.Printf("%snpm install --ignore-scripts%s  # Per-command\n", colorGreen, colorReset)
	fmt.Printf("%snpm config set ignore-scripts true%s  # Global\n", colorGreen, colorReset)
	fmt.Println()
	fmt.Println("📚 https://www.nodejs-security.com/blog/npm-ignore-scripts-best-practices")
	fmt.Println("📚 https://github.com/wiz-sec-public/wiz-research-iocs")
}

// ExportJSON exports findings to a JSON file
func (s *DiskScanner) ExportJSON(filename string) error {
	report := struct {
		ScanTime     string    `json:"scan_time"`
		TotalFiles   int64     `json:"total_files"`
		TotalDirs    int64     `json:"total_dirs"`
		PackagesDB   int       `json:"packages_in_db"`
		FindingCount int       `json:"finding_count"`
		Findings     []Finding `json:"findings"`
	}{
		ScanTime:     time.Now().Format(time.RFC3339),
		TotalFiles:   s.scannedFiles.Load(),
		TotalDirs:    s.scannedDirs.Load(),
		PackagesDB:   len(s.infectedPkgs),
		FindingCount: len(s.findings),
		Findings:     s.findings,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

