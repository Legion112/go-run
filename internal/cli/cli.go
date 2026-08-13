package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// Run dispatches gotun subcommands.
func Run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gotun <fetch|apply|clear>")
	}
	switch args[0] {
	case "fetch":
		return runFetch(args[1:])
	case "apply":
		return runApply(args[1:])
	case "clear":
		return runClear(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runFetch(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	out := fs.String("out", "prefixes.txt", "output prefix list path")
	country := fs.String("country", "RU", "ISO country code to extract")
	license := fs.String("license", os.Getenv("MAXMIND_LICENSE_KEY"), "MaxMind license key (CSV download)")
	mmdb := fs.String("mmdb", "", "path to local GeoIP2/GeoLite2 City or Country MMDB")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return FetchPrefixes(*license, *country, *out, *mmdb)
}

func runApply(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	prefixesPath := fs.String("prefixes", "", "path to CIDR list (one per line) or MaxMind-shaped fixture dir")
	endpoint := fs.String("endpoint", "", "WireGuard peer endpoint IP (underlay)")
	wgConf := fs.String("wg-config", "", "optional path to wg-quick style config (exit hop)")
	wgClients := fs.String("wg-clients-config", "", "optional path to wg-quick style config (inbound clients iface)")
	tunnelUp := fs.String("tunnel-up", "true", "whether tunnel should carry traffic (true|false)")
	lan := fs.String("lan", "", "LAN CIDR to exclude from marking and for home isolation (comma-separated)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	up := strings.EqualFold(*tunnelUp, "true") || *tunnelUp == "1"
	return Apply(*prefixesPath, *endpoint, *wgConf, *wgClients, *lan, up)
}

func runClear(args []string) error {
	fs := flag.NewFlagSet("clear", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	return Clear()
}
