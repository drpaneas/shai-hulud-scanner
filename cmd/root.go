package cmd

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	// Global flags
	workers    int
	outputJSON string
	offline    bool
	verbose    bool

	// Version info
	Version   = "1.0.0"
	BuildDate = "2024-11-27"
)

// ANSI colors
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
)

var rootCmd = &cobra.Command{
	Use:   "shai-hulud-scanner",
	Short: "🐛 Shai-Hulud v2 Malware Scanner",
	Long: fmt.Sprintf(`%s%s
   _____ _           _       _    _       _           _   ___  
  / ____| |         (_)     | |  | |     | |         | | |__ \ 
 | (___ | |__   __ _ _ ______| |__| |_   _| |_   _  __| |    ) |
  \___ \| '_ \ / _' | |______|  __  | | | | | | | |/ _' |   / / 
  ____) | | | | (_| | |      | |  | | |_| | | |_| | (_| |  / /_ 
 |_____/|_| |_|\__,_|_|      |_|  |_|\__,_|_|\__,_|\__,_| |____|
                                                                
%s%s  MALWARE SCANNER - Ultra-fast npm supply chain attack detection%s

Detects indicators of the Shai-Hulud v2 npm supply chain attack, including:
  • Infected npm packages from the Wiz IOC database (800+ packages)
  • Malicious files: bun_environment.js, setup_bun.js
  • Exfiltration data: cloud.json, contents.json, truffleSecrets.json
  • Backdoor workflows: .github/workflows/discussion.yaml
  • Hidden malware directories: .truffler-cache
  • Suspicious network connections and shell history
  • Persistence: git hooks, cron jobs, SSH keys, PATH hijacking
  • Extensions: VS Code, Chrome, Firefox, Edge browser extensions
  • Containers: Docker privileged containers, suspicious images
  • Privilege escalation: SUID binaries, LD_PRELOAD, sudoers

Sources:
  • https://about.gitlab.com/blog/gitlab-discovers-widespread-npm-supply-chain-attack/
  • https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
  • https://github.com/wiz-sec-public/wiz-research-iocs

Example usage:
  shai-hulud-scanner scan                    # Scan current directory
  shai-hulud-scanner scan --home             # Scan home directory  
  shai-hulud-scanner scan --full             # Full scan (disk + network + history)
  shai-hulud-scanner scan -p /path/to/scan   # Scan specific path
`, ColorBold, ColorCyan, ColorReset, ColorBold, ColorReset),
	Version: Version,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	// Default workers: 8x CPU cores, minimum 64
	defaultWorkers := runtime.NumCPU() * 8
	if defaultWorkers < 64 {
		defaultWorkers = 64
	}

	// Global persistent flags
	rootCmd.PersistentFlags().IntVarP(&workers, "workers", "w", defaultWorkers, "Number of worker goroutines")
	rootCmd.PersistentFlags().StringVarP(&outputJSON, "json", "j", "", "Export findings to JSON file")
	rootCmd.PersistentFlags().BoolVar(&offline, "offline", false, "Run in offline mode (limited package list)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	// Maximize parallelism
	runtime.GOMAXPROCS(runtime.NumCPU())
}
