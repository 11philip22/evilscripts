package main

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/Ullaakut/nmap"

	"github.com/OWASP/Amass/config"
	"github.com/OWASP/Amass/enum"
	"github.com/OWASP/Amass/services"
)

func typeOf(v interface{}) string {
	return reflect.TypeOf(v).String()
}

func stringInSlice(slice []string, val string) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}
	return -1, false
}

var (
	ipRegex, _ = regexp.Compile(
		`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`)
)

func isValidIpv4(ipAddress string) bool {
	ipAddress = strings.Trim(ipAddress, " ")
	return ipRegex.MatchString(ipAddress)
}

func pingScan(target string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(target),
		nmap.WithPingScan(),
		nmap.WithContext(ctx),
	)
	if err != nil {
		return false, err
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		return false, err
	}
	if warnings != nil {
		fmt.Printf("Warnings: \n %v", warnings)
	}

	if len(result.Hosts) > 0 {
		for _, host := range result.Hosts {
			if host.Status.State == "up" {
				return true, nil
			}
		}
	}
	return false, nil
}

func portScan(target string, outputFolder string) (*nmap.Run, string, error) {
	//fmt.Println("Starting portscan", target)

	nmapFolder := filepath.Join(outputFolder, "nmap")
	if _, err := os.Stat(nmapFolder); os.IsNotExist(err) {
		err := os.Mkdir(nmapFolder, 0755)
		if err != nil {
			return nil, "", err
		}
	}
	fileName := fmt.Sprintf("%s.txt", target)
	outputFile := filepath.Join(nmapFolder, fileName)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(target),
		nmap.WithPorts("1-65535"),
		nmap.WithSkipHostDiscovery(),
		nmap.WithAggressiveScan(),
		nmap.WithContext(ctx),
		// Write to file
		nmap.WithCustomArguments("-oN"),
		nmap.WithCustomArguments(outputFile),
	)
	if err != nil {
		return nil, "", err
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		return nil, "", err
	}
	if warnings != nil {
		fmt.Printf("Warnings: \n %v", warnings)
	}

	return result, outputFile, nil
}

func main() {
	target := os.Args[1]
	outputFolder := os.Args[2]
	projectFolder := filepath.Join(outputFolder, target)

	if _, err := os.Stat(projectFolder); os.IsNotExist(err) {
		err := os.MkdirAll(projectFolder, 0755)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())

	sys, err := services.NewLocalSystem(config.NewConfig())
	if err != nil {
		fmt.Println(err)
		return
	}

	e := enum.NewEnumeration(sys)
	if e == nil {
		fmt.Println(err)
		return
	}

	go func() {
		var knownHosts []string
		for result := range e.Output {
			ipAddress := result.Addresses[0].Address

			// Check if ipv4
			ipString := ipAddress.String()
			if isValidIpv4(ipString) {

				_, inSlice := stringInSlice(knownHosts, ipString)
				// If ip is not known proceed
				if inSlice == false {
					// Add ip to known ip list
					knownHosts = append(knownHosts, ipString)

					go func(ip string) {
						up, err := pingScan(ip)
						if err != nil {
							fmt.Println(err)
						}
						if up {
							result, _, err := portScan(ip, projectFolder)
							if err != nil {
								fmt.Println(err)
							}
							if result != nil {
								fmt.Println(result)
							}
						}
					}(ipString)
				}
			}
		}
	}()

	// Setup the most basic amass configuration
	e.Config.AddDomain(target)
	err = e.Start()
	if err != nil {
		fmt.Println(err)
		return
	}
}
