package scanner

import (
	"bufio"
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

// IOC Data Sources
const (
	// Wiz Research - Shai-Hulud v2 specific packages
	WizIOCPackagesURL = "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv"

	// OSSF Malicious Packages - Broad malicious npm package database
	OSSFMaliciousPackagesURL = "https://raw.githubusercontent.com/Red-Hat-Information-Security/Incident-Response/refs/heads/main/data/ossf-malicious-npm-packages.txt"

	// RHIS Malicious Packages - Red Hat InfoSec with campaign attribution
	RHISMaliciousPackagesURL = "https://raw.githubusercontent.com/Red-Hat-Information-Security/Incident-Response/refs/heads/main/data/rhis-malicious-npm-packages.csv"

	// RHIS Host IOCs - File and directory indicators of compromise
	RHISHostIOCsURL = "https://raw.githubusercontent.com/Red-Hat-Information-Security/Incident-Response/refs/heads/main/data/rhis-malicious-npm-package-host-iocs.csv"
)

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
	Campaign    string `json:"campaign,omitempty"`
}

// PackageIOC represents a malicious package with version and campaign info
type PackageIOC struct {
	Versions map[string]bool
	Campaign string
}

// HostIOC represents a file or directory indicator of compromise
type HostIOC struct {
	IOCType     string         // "file" or "directory"
	Pattern     *regexp.Regexp // Compiled glob pattern
	Description string
	Campaign    string
}

// DiskScanner handles filesystem scanning
type DiskScanner struct {
	findings      []Finding
	findingsMutex sync.Mutex
	scannedFiles  atomic.Int64
	scannedDirs   atomic.Int64
	infectedPkgs  map[string]*PackageIOC
	hostIOCs      []HostIOC
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
		infectedPkgs: make(map[string]*PackageIOC),
		hostIOCs:     make([]HostIOC, 0),
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

// fetchInfectedPackages downloads IOC lists from multiple sources
func (s *DiskScanner) fetchInfectedPackages() error {
	client := &http.Client{Timeout: 30 * time.Second}
	var fetchErrors []string

	// 1. Fetch Wiz Research IOC list (Shai-Hulud specific)
	fmt.Printf("%s[INFO]%s Fetching Wiz Research IOC list...\n", colorBlue, colorReset)
	if err := s.fetchWizIOCs(client); err != nil {
		fetchErrors = append(fetchErrors, fmt.Sprintf("Wiz: %v", err))
	}

	// 2. Fetch OSSF Malicious Packages (broad coverage)
	fmt.Printf("%s[INFO]%s Fetching OSSF malicious package database...\n", colorBlue, colorReset)
	if err := s.fetchOSSFPackages(client); err != nil {
		fetchErrors = append(fetchErrors, fmt.Sprintf("OSSF: %v", err))
	}

	// 3. Fetch RHIS Malicious Packages (with campaign attribution)
	fmt.Printf("%s[INFO]%s Fetching RHIS malicious package database...\n", colorBlue, colorReset)
	if err := s.fetchRHISPackages(client); err != nil {
		fetchErrors = append(fetchErrors, fmt.Sprintf("RHIS: %v", err))
	}

	// 4. Fetch RHIS Host IOCs (file/directory patterns)
	fmt.Printf("%s[INFO]%s Fetching RHIS host IOC database...\n", colorBlue, colorReset)
	if err := s.fetchRHISHostIOCs(client); err != nil {
		fetchErrors = append(fetchErrors, fmt.Sprintf("RHIS Host IOCs: %v", err))
	}

	if len(s.infectedPkgs) == 0 {
		return fmt.Errorf("failed to fetch any IOC databases: %v", fetchErrors)
	}

	if len(fetchErrors) > 0 {
		fmt.Printf("%s[WARN]%s Some IOC sources failed: %v\n", colorYellow, colorReset, fetchErrors)
	}

	return nil
}

// fetchWizIOCs fetches Shai-Hulud specific IOCs from Wiz Research
func (s *DiskScanner) fetchWizIOCs(client *http.Client) error {
	resp, err := client.Get(WizIOCPackagesURL)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return s.parseWizCSV(resp.Body)
}

// fetchOSSFPackages fetches the OSSF malicious package list
func (s *DiskScanner) fetchOSSFPackages(client *http.Client) error {
	resp, err := client.Get(OSSFMaliciousPackagesURL)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return s.parseOSSFPackages(resp.Body)
}

// fetchRHISPackages fetches RHIS malicious packages with campaign info
func (s *DiskScanner) fetchRHISPackages(client *http.Client) error {
	resp, err := client.Get(RHISMaliciousPackagesURL)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return s.parseRHISPackages(resp.Body)
}

// fetchRHISHostIOCs fetches file/directory IOC patterns
func (s *DiskScanner) fetchRHISHostIOCs(client *http.Client) error {
	resp, err := client.Get(RHISHostIOCsURL)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return s.parseRHISHostIOCs(resp.Body)
}

// parseWizCSV parses the Wiz Research CSV format
func (s *DiskScanner) parseWizCSV(reader io.Reader) error {
	csvReader := csv.NewReader(reader)
	header, err := csvReader.Read()
	if err != nil {
		return fmt.Errorf("failed to read CSV header: %w", err)
	}

	if len(header) < 2 || header[0] != "Package" || header[1] != "Version" {
		return fmt.Errorf("unexpected CSV format")
	}

	versionRegex := regexp.MustCompile(`=\s*(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?)`)
	count := 0

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
			s.infectedPkgs[packageName] = &PackageIOC{
				Versions: make(map[string]bool),
				Campaign: "Shai-Hulud-v2",
			}
			count++
		}

		if len(record) >= 2 && record[1] != "" {
			for _, match := range versionRegex.FindAllStringSubmatch(record[1], -1) {
				if len(match) >= 2 {
					s.infectedPkgs[packageName].Versions[strings.TrimSpace(match[1])] = true
				}
			}
		}
	}

	fmt.Printf("%s[INFO]%s Loaded %d packages from Wiz Research\n", colorGreen, colorReset, count)
	return nil
}

// parseOSSFPackages parses the OSSF malicious packages list (name@version format)
func (s *DiskScanner) parseOSSFPackages(reader io.Reader) error {
	scanner := bufio.NewScanner(reader)
	count := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Format: package_name@version
		parts := strings.Split(line, "@")
		if len(parts) < 2 {
			continue
		}

		packageName := strings.ToLower(parts[0])
		version := strings.ToLower(parts[1])

		if s.infectedPkgs[packageName] == nil {
			s.infectedPkgs[packageName] = &PackageIOC{
				Versions: make(map[string]bool),
				Campaign: "OSSF-Malicious-Packages",
			}
			count++
		}

		s.infectedPkgs[packageName].Versions[version] = true
	}

	fmt.Printf("%s[INFO]%s Loaded %d packages from OSSF database\n", colorGreen, colorReset, count)
	return scanner.Err()
}

// parseRHISPackages parses the RHIS CSV with campaign attribution
func (s *DiskScanner) parseRHISPackages(reader io.Reader) error {
	csvReader := csv.NewReader(reader)
	header, err := csvReader.Read()
	if err != nil {
		return fmt.Errorf("failed to read CSV header: %w", err)
	}

	// Find column indices
	pkgNameIdx, pkgVersionIdx, campaignIdx := -1, -1, -1
	for i, col := range header {
		switch strings.ToLower(strings.TrimSpace(col)) {
		case "package_name":
			pkgNameIdx = i
		case "package_version":
			pkgVersionIdx = i
		case "campaign_name":
			campaignIdx = i
		}
	}

	if pkgNameIdx == -1 || pkgVersionIdx == -1 {
		return fmt.Errorf("missing required columns in RHIS CSV")
	}

	count := 0
	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(record) <= pkgNameIdx || len(record) <= pkgVersionIdx {
			continue
		}

		packageName := strings.TrimSpace(record[pkgNameIdx])
		version := strings.TrimSpace(record[pkgVersionIdx])
		campaign := ""
		if campaignIdx >= 0 && len(record) > campaignIdx {
			campaign = strings.TrimSpace(record[campaignIdx])
		}

		if packageName == "" || version == "" {
			continue
		}

		if s.infectedPkgs[packageName] == nil {
			s.infectedPkgs[packageName] = &PackageIOC{
				Versions: make(map[string]bool),
				Campaign: campaign,
			}
			count++
		} else if campaign != "" && s.infectedPkgs[packageName].Campaign == "" {
			// Update campaign if we have one and previous entry didn't
			s.infectedPkgs[packageName].Campaign = campaign
		}

		s.infectedPkgs[packageName].Versions[version] = true
	}

	fmt.Printf("%s[INFO]%s Loaded %d packages from RHIS database\n", colorGreen, colorReset, count)
	return nil
}

// parseRHISHostIOCs parses the host IOC CSV (file/directory patterns)
func (s *DiskScanner) parseRHISHostIOCs(reader io.Reader) error {
	csvReader := csv.NewReader(reader)
	header, err := csvReader.Read()
	if err != nil {
		return fmt.Errorf("failed to read CSV header: %w", err)
	}

	// Find column indices
	iocTypeIdx, iocValueIdx, descIdx, campaignIdx := -1, -1, -1, -1
	for i, col := range header {
		switch strings.ToLower(strings.TrimSpace(col)) {
		case "ioc_type":
			iocTypeIdx = i
		case "ioc_value":
			iocValueIdx = i
		case "ioc_description":
			descIdx = i
		case "campaign_name":
			campaignIdx = i
		}
	}

	if iocTypeIdx == -1 || iocValueIdx == -1 {
		return fmt.Errorf("missing required columns in RHIS Host IOC CSV")
	}

	homeDir, _ := os.UserHomeDir()
	count := 0

	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(record) <= iocTypeIdx || len(record) <= iocValueIdx {
			continue
		}

		iocType := strings.ToLower(strings.TrimSpace(record[iocTypeIdx]))
		iocValue := strings.TrimSpace(record[iocValueIdx])

		// Only process file and directory IOCs
		if iocType != "file" && iocType != "directory" {
			continue
		}

		// Expand ~ to home directory
		if strings.HasPrefix(iocValue, "~/") {
			iocValue = filepath.Join(homeDir, iocValue[2:])
		} else if iocValue == "~" {
			iocValue = homeDir
		}

		// Convert glob pattern to regex
		pattern, err := globToRegex(iocValue)
		if err != nil {
			continue
		}

		description := ""
		if descIdx >= 0 && len(record) > descIdx {
			description = strings.TrimSpace(record[descIdx])
		}

		campaign := ""
		if campaignIdx >= 0 && len(record) > campaignIdx {
			campaign = strings.TrimSpace(record[campaignIdx])
		}

		s.hostIOCs = append(s.hostIOCs, HostIOC{
			IOCType:     iocType,
			Pattern:     pattern,
			Description: description,
			Campaign:    campaign,
		})
		count++
	}

	fmt.Printf("%s[INFO]%s Loaded %d host IOC patterns from RHIS database\n", colorGreen, colorReset, count)
	return nil
}

// globToRegex converts a glob pattern to a compiled regex
func globToRegex(pattern string) (*regexp.Regexp, error) {
	// Escape special regex characters except * and ?
	escaped := regexp.QuoteMeta(pattern)

	// Convert glob wildcards to regex
	// ** matches any path (including separators)
	escaped = strings.ReplaceAll(escaped, `\*\*`, `.*`)
	// * matches anything except path separator
	escaped = strings.ReplaceAll(escaped, `\*`, `[^/]*`)
	// ? matches single character
	escaped = strings.ReplaceAll(escaped, `\?`, `.`)

	// Anchor the pattern
	escaped = "^" + escaped + "$"

	return regexp.Compile(escaped)
}

func (s *DiskScanner) loadOfflinePackages() {
	fmt.Printf("%s[WARN]%s Running in offline mode with limited package list\n", colorYellow, colorReset)

	// Critical packages from Shai-Hulud 2.0 "Second Coming" campaign
	// Sources: Wiz, Datadog, Tenable, PostHog, Postman, Zapier incident reports
	criticalPackages := map[string]struct {
		versions []string
		campaign string
	}{
		// Postman - 17 packages, 51 versions affected
		"@postman/tunnel-agent": {[]string{"0.6.5", "0.6.6", "0.6.7", "2.0.19", "2.0.20", "2.0.21"}, "Shai-Hulud-v2"},

		// PostHog - confirmed affected versions
		"posthog-node": {[]string{"4.3.2", "4.3.3", "4.18.1", "5.11.3", "5.13.3"}, "Shai-Hulud-v2"},
		"posthog-js":   {[]string{"1.205.1", "1.205.2", "1.297.3"}, "Shai-Hulud-v2"},

		// Zapier - confirmed affected versions
		"zapier-platform-cli":  {[]string{"18.0.2", "18.0.3", "18.0.4"}, "Shai-Hulud-v2"},
		"zapier-platform-core": {[]string{"18.0.2", "18.0.3", "18.0.4"}, "Shai-Hulud-v2"},
		"zapier-sdk":           {[]string{"18.0.2", "18.0.3", "18.0.4"}, "Shai-Hulud-v2"},
		"babel-preset-zapier":  {[]string{"1.0.0", "1.0.1"}, "Shai-Hulud-v2"},

		// AsyncAPI - patient zero
		"@asyncapi/cli":                   {[]string{"6.8.2", "6.8.3", "6.9.1", "6.10.1"}, "Shai-Hulud-v2"},
		"@asyncapi/specs":                 {[]string{"6.8.2", "6.8.3", "6.9.1", "6.10.1"}, "Shai-Hulud-v2"},
		"@asyncapi/openapi-schema-parser": {[]string{"3.0.25", "3.0.26"}, "Shai-Hulud-v2"},

		// ENS Domains
		"@ensdomains/hardhat-chai-matchers-viem": {[]string{"1.0.0", "1.0.1"}, "Shai-Hulud-v2"},
		"ethereum-ens":                           {[]string{"0.8.0", "0.8.1"}, "Shai-Hulud-v2"},

		// Other known affected
		"kill-port":                {[]string{"2.0.2", "2.0.3"}, "Shai-Hulud-v2"},
		"shell-exec":               {[]string{"1.1.3", "1.1.4"}, "Shai-Hulud-v2"},
		"@browserbasehq/stagehand": {[]string{"3.0.4"}, "Shai-Hulud-v2"},
	}

	for pkg, info := range criticalPackages {
		s.infectedPkgs[pkg] = &PackageIOC{
			Versions: make(map[string]bool),
			Campaign: info.campaign,
		}
		for _, v := range info.versions {
			s.infectedPkgs[pkg].Versions[v] = true
		}
	}

	fmt.Printf("%s[INFO]%s Loaded %d critical packages for offline scanning\n", colorBlue, colorReset, len(s.infectedPkgs))
}

func (s *DiskScanner) addFinding(finding Finding) {
	s.findingsMutex.Lock()
	s.findings = append(s.findings, finding)
	s.findingsMutex.Unlock()
}

// checkHostIOCs checks a path against host IOC patterns
func (s *DiskScanner) checkHostIOCs(path string, iocType string) {
	for _, ioc := range s.hostIOCs {
		if ioc.IOCType != iocType {
			continue
		}
		if ioc.Pattern.MatchString(path) {
			s.addFinding(Finding{
				Type:        "HOST_IOC",
				Severity:    "CRITICAL",
				Path:        path,
				Description: fmt.Sprintf("IoC: %s", ioc.Description),
				Details:     fmt.Sprintf("Pattern matched: %s", ioc.Pattern.String()),
				Campaign:    ioc.Campaign,
			})
			return // Only report first match
		}
	}
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
	fmt.Printf("%s[INFO]%s Tracking %d infected packages\n", colorBlue, colorReset, len(s.infectedPkgs))
	fmt.Printf("%s[INFO]%s Tracking %d host IOC patterns\n\n", colorBlue, colorReset, len(s.hostIOCs))

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
						Campaign:    "Shai-Hulud-v2",
					})
				}

				// Check directory against host IOC patterns
				s.checkHostIOCs(path, "directory")

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

	// Check file against host IOC patterns
	s.checkHostIOCs(path, "file")

	switch name {
	case "bun_environment.js":
		s.addFinding(Finding{
			Type:        "MALICIOUS_FILE",
			Severity:    "CRITICAL",
			Path:        path,
			Description: "Found bun_environment.js - Main Shai-Hulud malware payload",
			Details:     "Obfuscated malware that steals credentials and propagates.",
			Campaign:    "Shai-Hulud-v2",
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
				Campaign:    "Shai-Hulud-v2",
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
			Campaign:    "Shai-Hulud-v2",
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
			Campaign:    "Shai-Hulud-v2",
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
				Campaign:    "Shai-Hulud-v2",
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
			Campaign:    "Shai-Hulud-v2",
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

	// HIGH-CONFIDENCE patterns - these alone indicate malware
	// These are unique to Shai-Hulud and unlikely to appear in legitimate code
	highConfidencePatterns := [][]byte{
		sha1HuludPattern,               // SHA1HULUD
		sha1HuludPattern2,              // Sha1-Hulud
		[]byte("The Second Coming"),    // Campaign name
		[]byte("The Continued Coming"), // Campaign name variant
		[]byte(".truffler-cache"),      // Malware-specific cache directory
		[]byte("downloadAndSetupBun"),  // Malware function name
		[]byte("bun_environment.js"),   // Full malware filename
		[]byte("setup_bun.js"),         // Full malware filename
	}

	for _, pattern := range highConfidencePatterns {
		if bytes.Contains(content, pattern) {
			s.addFinding(Finding{
				Type:        "BACKDOOR_WORKFLOW",
				Severity:    "CRITICAL",
				Path:        path,
				Description: "GitHub workflow contains Shai-Hulud malware pattern",
				Details:     fmt.Sprintf("Found: %s", string(pattern)),
				Campaign:    "Shai-Hulud-v2",
			})
			return
		}
	}

	// MEDIUM-CONFIDENCE patterns - require MULTIPLE indicators
	// These can appear in legitimate code (trufflehog is a valid security tool)
	mediumConfidencePatterns := [][]byte{
		[]byte("trufflehog"),      // Legitimate secret scanning tool, but also used by malware
		[]byte("bun_environment"), // Could be legitimate bun config
		[]byte("setup_bun"),       // Could be legitimate bun setup
	}

	// Count how many medium-confidence patterns match
	matchCount := 0
	var matchedPatterns []string
	for _, pattern := range mediumConfidencePatterns {
		if bytes.Contains(content, pattern) {
			matchCount++
			matchedPatterns = append(matchedPatterns, string(pattern))
		}
	}

	// Also check for attack-vector indicators
	hasSelfHosted := bytes.Contains(content, selfHostedPattern)
	hasDiscussionTrigger := bytes.Contains(content, discussionBody) || bytes.Contains(content, discussionPattern)

	// Only flag if we have multiple medium-confidence patterns
	// OR a medium-confidence pattern combined with attack-vector indicators
	if matchCount >= 2 {
		s.addFinding(Finding{
			Type:        "SUSPICIOUS_WORKFLOW",
			Severity:    "HIGH",
			Path:        path,
			Description: "GitHub workflow contains multiple suspicious patterns",
			Details:     fmt.Sprintf("Found: %s", strings.Join(matchedPatterns, ", ")),
			Campaign:    "Shai-Hulud-v2",
		})
		return
	}

	if matchCount >= 1 && hasSelfHosted && hasDiscussionTrigger {
		s.addFinding(Finding{
			Type:        "SUSPICIOUS_WORKFLOW",
			Severity:    "HIGH",
			Path:        path,
			Description: "GitHub workflow with suspicious pattern + attack vector indicators",
			Details:     fmt.Sprintf("Found: %s (with self-hosted runner and discussion trigger)", strings.Join(matchedPatterns, ", ")),
			Campaign:    "Shai-Hulud-v2",
		})
		return
	}

	// Check for the classic attack vector combination (even without other patterns)
	if hasSelfHosted && hasDiscussionTrigger {
		s.addFinding(Finding{
			Type:        "SUSPICIOUS_WORKFLOW",
			Severity:    "MEDIUM",
			Path:        path,
			Description: "GitHub workflow with self-hosted runner and discussion trigger",
			Details:     "This pattern matches the Shai-Hulud attack vector. Verify this is intentional.",
			Campaign:    "Shai-Hulud-v2",
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
						Campaign:    "Shai-Hulud-v2",
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
						Campaign:    "Unknown",
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

	// Get the project directory (where package.json is located)
	projectDir := filepath.Dir(path)

	for depName := range allDeps {
		pkgIOC, infected := s.infectedPkgs[depName]
		if !infected {
			continue
		}

		// Auto-verify: Check the actual installed version in node_modules
		verdict := s.verifyInstalledVersion(projectDir, depName, pkgIOC)

		switch verdict.status {
		case "INFECTED":
			s.addFinding(Finding{
				Type:        "INFECTED_DEPENDENCY",
				Severity:    "CRITICAL",
				Path:        path,
				Description: fmt.Sprintf("🚨 CONFIRMED: Package '%s' has INFECTED dependency: %s@%s", pkgFull.Name, depName, verdict.version),
				Details:     fmt.Sprintf("Verdict: INFECTED - Installed version %s matches known malicious version", verdict.version),
				Campaign:    pkgIOC.Campaign,
			})
		case "SAFE":
			// Don't report - installed version is not in the malicious list
			// Optionally log at debug level
		case "NOT_INSTALLED":
			// Dependency listed but not installed - skip silently
		case "UNKNOWN":
			// Could not determine version - only report for high-risk campaigns
			if pkgIOC.Campaign == "Shai-Hulud-v2" {
				s.addFinding(Finding{
					Type:        "UNVERIFIED_DEPENDENCY",
					Severity:    "MEDIUM",
					Path:        path,
					Description: fmt.Sprintf("Package '%s' depends on package with malicious versions: %s", pkgFull.Name, depName),
					Details:     fmt.Sprintf("Verdict: UNVERIFIED - Could not read installed version. Run: npm ls %s", depName),
					Campaign:    pkgIOC.Campaign,
				})
			}
		}
	}
}

// VersionVerdict represents the result of version verification
type VersionVerdict struct {
	status  string // "INFECTED", "SAFE", "NOT_INSTALLED", "UNKNOWN"
	version string
}

// verifyInstalledVersion checks the actual installed version against known malicious versions
func (s *DiskScanner) verifyInstalledVersion(projectDir, depName string, pkgIOC *PackageIOC) VersionVerdict {
	// Handle scoped packages (e.g., @babel/core -> node_modules/@babel/core)
	depPath := depName
	if strings.HasPrefix(depName, "@") {
		// Scoped package: @scope/name
		depPath = depName
	}

	// Check in node_modules
	nodeModulesPath := filepath.Join(projectDir, "node_modules", depPath, "package.json")

	content, err := os.ReadFile(nodeModulesPath)
	if err != nil {
		// Package not installed or can't read
		if os.IsNotExist(err) {
			return VersionVerdict{status: "NOT_INSTALLED", version: ""}
		}
		return VersionVerdict{status: "UNKNOWN", version: ""}
	}

	var pkg struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(content, &pkg); err != nil {
		return VersionVerdict{status: "UNKNOWN", version: ""}
	}

	installedVersion := strings.TrimSpace(pkg.Version)
	if installedVersion == "" {
		return VersionVerdict{status: "UNKNOWN", version: ""}
	}

	// Check if installed version is in the malicious versions list
	if pkgIOC.Versions[installedVersion] {
		return VersionVerdict{status: "INFECTED", version: installedVersion}
	}

	// Version not in malicious list - SAFE
	return VersionVerdict{status: "SAFE", version: installedVersion}
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

	if pkgIOC, exists := s.infectedPkgs[pkg.Name]; exists {
		if len(pkgIOC.Versions) > 0 {
			if pkgIOC.Versions[pkg.Version] {
				s.addFinding(Finding{
					Type:        "INFECTED_PACKAGE",
					Severity:    "CRITICAL",
					Path:        path,
					Description: fmt.Sprintf("Found infected package: %s@%s", pkg.Name, pkg.Version),
					Details:     "This package version is compromised.",
					Campaign:    pkgIOC.Campaign,
				})
			}
		} else {
			s.addFinding(Finding{
				Type:        "SUSPICIOUS_PACKAGE",
				Severity:    "HIGH",
				Path:        path,
				Description: fmt.Sprintf("Potentially infected package: %s@%s", pkg.Name, pkg.Version),
				Details:     "Package in IOC list but version-specific data unavailable.",
				Campaign:    pkgIOC.Campaign,
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
						Campaign:    "Shai-Hulud-v2",
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
			if f.Campaign != "" {
				fmt.Printf("  %s🎯 Campaign:%s %s\n", colorCyan, colorReset, f.Campaign)
			}
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

	// Print user identity information for incident reporting
	s.printUserIdentity()

	s.printPreventionTips()
}

// printUserIdentity prints user/host information for incident reporting
func (s *DiskScanner) printUserIdentity() {
	fmt.Printf("\n%s%s╔══════════════════════════════════════════════════════════════════╗%s\n", colorBold, colorPurple, colorReset)
	fmt.Printf("%s%s║  📋 INCLUDE THIS IN YOUR INFOSEC TICKET                           ║%s\n", colorBold, colorPurple, colorReset)
	fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════╝%s\n", colorBold, colorPurple, colorReset)
	fmt.Println()

	// Get username
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME") // Windows
	}
	if username == "" {
		username = "unknown"
	}

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Get timestamp
	timestamp := time.Now().Unix()

	fmt.Printf("  %s- Username:%s %s\n", colorCyan, colorReset, username)
	fmt.Printf("  %s- Hostname:%s %s\n", colorCyan, colorReset, hostname)
	fmt.Printf("  %s- Timestamp:%s %d\n", colorCyan, colorReset, timestamp)
	fmt.Printf("  %s- Scan Time:%s %s\n", colorCyan, colorReset, time.Now().Format(time.RFC3339))
	fmt.Println()
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
