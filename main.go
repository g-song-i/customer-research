package main

import (
	"customer_research/config"
	"customer_research/services/reverseip"
	"customer_research/services/virustotal"
	"customer_research/utils"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
)

type IPDetail struct {
	IPs           []string `json:"ips"`
	ReverseLookup []string `json:"reverse_lookup"`
}

type Output struct {
	Domain      string              `json:"domain"`
	Subdomains  []string            `json:"subdomains"`
	IPAddresses map[string]IPDetail `json:"ip_addresses"`
}

func main() {
	action := flag.String("action", "", "Action to perform (e.g., subdomain_report, get_dns_info)")
	domain := flag.String("domain", "", "Domain to process")
	flag.Parse()

	if *action == "" || *domain == "" {
		log.Fatalf("Usage: %s -action=ACTION -domain=DOMAIN", os.Args[0])
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	switch *action {
	case "subdomain_report":
		runSubdomainReport(*domain, cfg)
	case "get_dns_info":
		getDNSInfo(*domain, cfg)
	default:
		log.Fatalf("Unknown action: %s", *action)
	}
}

func runSubdomainReport(domain string, cfg *config.Config) {
	limit := 300
	fmt.Printf("Fetching subdomains and IPs for %s...\n", domain)
	subdomainsWithIPs, err := virustotal.GetSubdomains(domain, cfg.VirusTotalAPIKey, limit)
	if err != nil {
		log.Fatalf("Error fetching subdomains and IPs: %v", err)
	}

	ipResults := make(map[string]IPDetail)
	var subdomains []string
	for subdomain, ips := range subdomainsWithIPs {
		subdomains = append(subdomains, subdomain)
		fmt.Printf("Resolving reverse lookup for subdomain: %s\n", subdomain)

		reverseResults := []string{}
		for _, ip := range ips {
			reverse, err := reverseip.GetReverseIP(ip)
			if err != nil {
				log.Printf("Error reverse looking up IP %s for %s: %v", ip, subdomain, err)
				continue
			}
			reverseResults = append(reverseResults, reverse...)
		}

		ipResults[subdomain] = IPDetail{
			IPs:           ips,
			ReverseLookup: reverseResults,
		}
	}

	output := Output{
		Domain:      domain,
		Subdomains:  subdomains,
		IPAddresses: ipResults,
	}

	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		log.Fatalf("Error marshaling output to JSON: %v", err)
	}

	fmt.Println(string(jsonData))

	savePath := utils.SaveResult(domain, jsonData)
	fmt.Printf("Results saved to: %s\n", savePath)
}

func getDNSInfo(domain string, cfg *config.Config) {
	fmt.Printf("Fetching DNS info for %s...\n", domain)

	domainInfo, err := virustotal.GetDomainInfo(domain, cfg.VirusTotalAPIKey)
	if err != nil {
		log.Fatalf("Error fetching DNS info for %s: %v", domain, err)
	}

	jsonData, err := json.MarshalIndent(domainInfo, "", "  ")
	if err != nil {
		log.Fatalf("Error marshaling domain info to JSON: %v", err)
	}

	fmt.Println(string(jsonData))

	savePath := utils.SaveResult(domain, jsonData)
	fmt.Printf("Results saved to: %s\n", savePath)
}
