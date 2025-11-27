package cmd

import (
	"bufio"
	"fmt"
	"os"

	"shai-hulud-scanner/scanner"

	"github.com/spf13/cobra"
)

var (
	scanPath        string
	homeDir         bool
	scanNetwork     bool
	scanHistory     bool
	scanAdvanced    bool
	scanPersistence bool
	fullScan        bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan for Shai-Hulud v2 malware indicators",
	Long: `Scan the filesystem for indicators of the Shai-Hulud v2 npm supply chain attack.

This command performs ultra-fast parallel disk scanning using godirwalk,
checking for malicious files, infected npm packages, and suspicious scripts.

Detection capabilities based on analysis from:
  • GitLab Security Research
  • Wiz Threat Research  
  • SentinelOne Labs
  • StepSecurity
  • Tenable Research
  • Mend.io (formerly WhiteSource)

Examples:
  shai-hulud-scanner scan                      # Scan current directory
  shai-hulud-scanner scan --home               # Scan entire home directory
  shai-hulud-scanner scan -p /path/to/project  # Scan specific path
  shai-hulud-scanner scan --full               # Full scan: all modules enabled
  shai-hulud-scanner scan --network            # Include network connection analysis
  shai-hulud-scanner scan --history            # Include shell history analysis
  shai-hulud-scanner scan --advanced           # Deep scan: obfuscation, runners, workflows
  shai-hulud-scanner scan --persist            # Persistence: git hooks, cron, SSH keys, PATH
  shai-hulud-scanner scan -j report.json       # Export results to JSON`,
	Run: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&scanPath, "path", "p", "", "Path to scan (default: current directory)")
	scanCmd.Flags().BoolVar(&homeDir, "home", false, "Scan entire home directory")
	scanCmd.Flags().BoolVarP(&scanNetwork, "network", "n", false, "Scan network connections for IoCs")
	scanCmd.Flags().BoolVar(&scanHistory, "history", false, "Scan shell history and credentials")
	scanCmd.Flags().BoolVarP(&scanAdvanced, "advanced", "a", false, "Advanced deep scan (obfuscation, runners, workflows)")
	scanCmd.Flags().BoolVar(&scanPersistence, "persist", false, "Scan for persistence (git hooks, cron, SSH, PATH hijack)")
	scanCmd.Flags().BoolVarP(&fullScan, "full", "f", false, "Full scan: disk + network + history + advanced + persistence")
}

func runScan(cmd *cobra.Command, args []string) {
	// Full scan enables all modes
	if fullScan {
		homeDir = true
		scanNetwork = true
		scanHistory = true
		scanAdvanced = true
		scanPersistence = true
	}

	// Determine scan path
	if homeDir {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s[ERROR]%s Failed to get home directory: %v\n", ColorRed, ColorReset, err)
			os.Exit(1)
		}
		scanPath = home
	} else if scanPath == "" {
		var err error
		scanPath, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s[ERROR]%s Failed to get current directory: %v\n", ColorRed, ColorReset, err)
			os.Exit(1)
		}
	}

	// Verify path exists
	if _, err := os.Stat(scanPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "%s[ERROR]%s Path does not exist: %s\n", ColorRed, ColorReset, scanPath)
		os.Exit(1)
	}

	totalFindings := 0

	// Disk scan
	diskScanner := scanner.NewDiskScanner(workers, offline)
	diskScanner.Scan(scanPath)
	totalFindings += diskScanner.FindingCount()

	// Network scan
	if scanNetwork {
		netScanner := scanner.NewNetworkScanner()
		netFindings := netScanner.Run()
		totalFindings += len(netFindings)
	}

	// History/credentials scan
	if scanHistory {
		histScanner := scanner.NewHistoryScanner()
		histFindings := histScanner.Run()
		totalFindings += len(histFindings)
	}

	// Advanced deep scan
	if scanAdvanced {
		advScanner := scanner.NewAdvancedScanner()
		advFindings := advScanner.Run(scanPath)
		totalFindings += len(advFindings)
	}

	// Persistence mechanism scan
	if scanPersistence {
		persistScanner := scanner.NewPersistenceScanner()
		persistFindings := persistScanner.Run()
		totalFindings += len(persistFindings)
	}

	// Export JSON
	if outputJSON != "" {
		if err := diskScanner.ExportJSON(outputJSON); err != nil {
			fmt.Fprintf(os.Stderr, "%s[ERROR]%s Failed to export JSON: %v\n", ColorRed, ColorReset, err)
			os.Exit(1)
		}
		fmt.Printf("\n%s[INFO]%s Findings exported to: %s\n", ColorBlue, ColorReset, outputJSON)
	}

	// Summary
	if totalFindings > 0 {
		fmt.Printf("\n%s%s══════════════════════════════════════════════════════════════════%s\n", ColorBold, ColorRed, ColorReset)
		fmt.Printf("%s%s  TOTAL FINDINGS: %d - IMMEDIATE ACTION REQUIRED%s\n", ColorBold, ColorRed, totalFindings, ColorReset)
		fmt.Printf("%s%s══════════════════════════════════════════════════════════════════%s\n", ColorBold, ColorRed, ColorReset)
		fmt.Print("\nPress Enter to exit...")
		bufio.NewReader(os.Stdin).ReadBytes('\n')
		os.Exit(1)
	}
}
