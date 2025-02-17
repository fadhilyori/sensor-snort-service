package main

import (
	"fmt"
	"os"

	"github.com/mata-elang-stable/sensor-snort-service/internal/logger"
	"github.com/spf13/cobra"
)

var (
	appVersion = "dev"
	appCommit  = "none"
	appLicense = "MIT"
)

var log = logger.GetLogger()

var rootCmd = &cobra.Command{
	Use:   "mes-snort",
	Short: "mes-snort is a tool to collect and parse sensor data of Mata Elang system.",
	Args:  cobra.NoArgs,
	Run:   nil,
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
