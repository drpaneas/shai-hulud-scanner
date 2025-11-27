package cmd

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const WizIOCPackagesURL = "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv"

var checkCmd = &cobra.Command{
	Use:   "check [package@version]",
	Short: "Check if a specific npm package is in the IOC list",
	Long: `Check if a specific npm package and version is known to be infected.

Examples:
  shai-hulud-scanner check posthog-node@4.3.2
  shai-hulud-scanner check @asyncapi/specs@6.8.2
  shai-hulud-scanner check kill-port`,
	Args: cobra.MaximumNArgs(1),
	Run:  runCheck,
}

func init() {
	rootCmd.AddCommand(checkCmd)
}

func runCheck(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fmt.Printf("%s[ERROR]%s Please provide a package name to check\n", ColorRed, ColorReset)
		fmt.Println("Example: shai-hulud-scanner check posthog-node@4.3.2")
		return
	}

	input := args[0]
	var pkgName, pkgVersion string

	// Parse package@version format
	if idx := strings.LastIndex(input, "@"); idx > 0 {
		pkgName = input[:idx]
		pkgVersion = input[idx+1:]
	} else {
		pkgName = input
	}

	fmt.Printf("%s[INFO]%s Fetching IOC database from Wiz Research...\n", ColorBlue, ColorReset)

	// Fetch IOC list
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(WizIOCPackagesURL)
	if err != nil {
		fmt.Printf("%s[ERROR]%s Failed to fetch IOC list: %v\n", ColorRed, ColorReset, err)
		return
	}
	defer resp.Body.Close()

	// Parse CSV
	infectedPkgs := make(map[string][]string)
	csvReader := csv.NewReader(resp.Body)
	csvReader.Read() // Skip header

	versionRegex := regexp.MustCompile(`=\s*(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?)`)

	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(record) < 1 {
			continue
		}

		name := strings.TrimSpace(record[0])
		if name == "" {
			continue
		}

		var versions []string
		if len(record) >= 2 && record[1] != "" {
			matches := versionRegex.FindAllStringSubmatch(record[1], -1)
			for _, match := range matches {
				if len(match) >= 2 {
					versions = append(versions, strings.TrimSpace(match[1]))
				}
			}
		}
		infectedPkgs[name] = versions
	}

	fmt.Printf("%s[INFO]%s Loaded %d packages from IOC database\n\n", ColorGreen, ColorReset, len(infectedPkgs))

	// Check package
	if versions, exists := infectedPkgs[pkgName]; exists {
		if pkgVersion != "" {
			// Check specific version
			for _, v := range versions {
				if v == pkgVersion {
					fmt.Printf("%s%s⚠️  INFECTED: %s@%s is in the IOC list!%s\n", ColorBold, ColorRed, pkgName, pkgVersion, ColorReset)
					fmt.Println("\nThis package version is known to be compromised by Shai-Hulud v2.")
					fmt.Println("DO NOT install or use this version.")
					return
				}
			}
			fmt.Printf("%s✅ SAFE: %s@%s is NOT in the IOC list%s\n", ColorGreen, pkgName, pkgVersion, ColorReset)
			fmt.Printf("\nHowever, note that %s has infected versions: %v\n", pkgName, versions)
		} else {
			// Package exists, show all infected versions
			fmt.Printf("%s%s⚠️  WARNING: %s has infected versions!%s\n", ColorBold, ColorYellow, pkgName, ColorReset)
			fmt.Printf("\nInfected versions:\n")
			for _, v := range versions {
				fmt.Printf("  • %s@%s\n", pkgName, v)
			}
		}
	} else {
		fmt.Printf("%s✅ SAFE: %s is NOT in the IOC list%s\n", ColorGreen, pkgName, ColorReset)
	}
}
