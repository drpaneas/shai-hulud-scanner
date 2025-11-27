package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s%sShai-Hulud v2 Scanner%s\n", ColorBold, ColorCyan, ColorReset)
		fmt.Printf("  Version:    %s\n", Version)
		fmt.Printf("  Build Date: %s\n", BuildDate)
		fmt.Printf("  Go Version: %s\n", runtime.Version())
		fmt.Printf("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
		fmt.Printf("  CPUs:       %d\n", runtime.NumCPU())
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

