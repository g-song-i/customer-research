package main

import (
	"customer_research/config"
	"customer_research/services/virustotal"
	"customer_research/utils"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	action := flag.String("action", "", "Action to perform (e.g., subdomain_report, get_dns_info)")
	domain := flag.String("domain", "", "Domain to process")
	file := flag.String("file", "", "Input JSON file to process (required for export_excel)")
	flag.Parse()

	if *action == "" {
		log.Fatalf("Usage: %s -action=ACTION -domain=DOMAIN (or -file=FILE for export_excel)", os.Args[0])
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	switch *action {
	case "subdomain_report":
		if *domain == "" {
			log.Fatalf("Domain is required for subdomain_report action")
		}
		runSubdomainReport(*domain, cfg)
	case "get_dns_info":
		if *domain == "" {
			log.Fatalf("Domain is required for get_dns_info action")
		}
		getDNSInfo(*domain, cfg)
	case "export_excel":
		if *file == "" {
			log.Fatalf("File is required for export_excel action")
		}
		exportToExcel(*file)
	default:
		log.Fatalf("Unknown action: %s", *action)
	}
}

func runSubdomainReport(domain string, cfg *config.Config) {
	limit := 300
	fmt.Printf("Fetching subdomains and IPs for %s...\n", domain)

	result, err := virustotal.GetSubdomains(domain, cfg.VirusTotalAPIKey, limit)
	if err != nil {
		log.Fatalf("Error fetching subdomains: %v", err)
	}

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatalf("Error marshaling result to JSON: %v", err)
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

func exportToExcel(file string) {
	fmt.Printf("Exporting JSON data from %s to Excel...\n", file)

	outputFile, err := utils.ExportToExcel(file)
	if err != nil {
		log.Fatalf("Error exporting to Excel: %v", err)
	}

	fmt.Printf("Excel export completed successfully. File saved at: %s\n", outputFile)
}
