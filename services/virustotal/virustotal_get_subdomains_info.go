package virustotal

import (
	"customer_research/services/reverseip"
	"customer_research/services/asninfo"
	"customer_research/utils"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type IPDetail struct {
	IPs           []string `json:"ips"`
	ReverseLookup []string `json:"reverse_lookup"`
	ASN           []string `json:"asn"`
	Route         []string `json:"route"`
	OrgName       []string `json:"org_name"`
}

type Output struct {
	Domain      string              `json:"domain"`
	Subdomains  []string            `json:"subdomains"`
	IPAddresses map[string]IPDetail `json:"ip_addresses"`
}

type DomainObject struct {
	ID         string `json:"id"`
	Attributes struct {
		LastDNSRecords []DNSRecord `json:"last_dns_records"`
	} `json:"attributes"`
}

type SubdomainsResponse struct {
	Data []DomainObject `json:"data"`
	Meta struct {
		Count  int    `json:"count"`
		Cursor string `json:"cursor"`
	} `json:"meta"`
}

// It executes a chain of functions to get subdomain information
func GetSubdomains(domain, apiKey string, limit int) (*Output, error) {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=%d", domain, limit)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("x-apikey", apiKey)

	client := utils.NewHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch subdomains, status: %d", resp.StatusCode)
	}

	var response SubdomainsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	ipResults := make(map[string]IPDetail)
	var subdomains []string

	for _, obj := range response.Data {
		var ips []string
		for _, record := range obj.Attributes.LastDNSRecords {
			if record.Type == "A" {
				ips = append(ips, record.Value)
			}
		}

		reverseResults := resolveReverseLookups(ips)
		asnList := []string{}
		routeList := []string{}
		orgNameList := []string{}

		for _, ip := range ips {
			asnDetails, err := asninfo.GetASNInfo(ip)
			if err != nil {
				log.Printf("Error fetching ASN info for IP %s: %v", ip, err)
				continue
			}
			asnList = append(asnList, asnDetails.ASN)
			routeList = append(routeList, asnDetails.Route)
			orgNameList = append(orgNameList, asnDetails.OrgName)
		}

		ipResults[obj.ID] = IPDetail{
			IPs:           ips,
			ReverseLookup: reverseResults,
			ASN:           asnList,
			Route:         routeList,
			OrgName:       orgNameList,
		}
		
		subdomains = append(subdomains, obj.ID)
	}

	output := &Output{
		Domain:      domain,
		Subdomains:  subdomains,
		IPAddresses: ipResults,
	}
	return output, nil
}

func resolveReverseLookups(ips []string) []string {
	reverseResults := []string{}
	for _, ip := range ips {
		reverse, err := reverseip.GetReverseIP(ip)
		if err != nil {
			log.Printf("Error reverse looking up IP %s: %v", ip, err)
			continue
		}
		reverseResults = append(reverseResults, reverse...)
	}
	return reverseResults
}
