package virustotal

import (
	"customer_research/utils"
	"encoding/json"
	"fmt"
	"net/http"
)

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

func GetSubdomains(domain, apiKey string, limit int) (map[string][]string, error) {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=%d", domain, limit)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", apiKey)

	client := utils.NewHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch subdomains, status: %d", resp.StatusCode)
	}

	var response SubdomainsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	subdomainsWithIPs := make(map[string][]string)
	for _, obj := range response.Data {
		var ips []string
		for _, record := range obj.Attributes.LastDNSRecords {
			if record.Type == "A" {
				ips = append(ips, record.Value)
			}
		}
		subdomainsWithIPs[obj.ID] = ips
	}

	return subdomainsWithIPs, nil
}
