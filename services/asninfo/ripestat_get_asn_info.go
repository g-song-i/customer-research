package asninfo

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type RIPEstatResponse struct {
	Data struct {
		Records [][]struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"records"`
	} `json:"data"`
}

type ASNDetails struct {
	ASN      string `json:"asn"`
	Route    string `json:"route"`
	OrgName  string `json:"org_name"`
}

func GetASNInfo(ip string) (*ASNDetails, error) {
	url := fmt.Sprintf("https://stat.ripe.net/data/whois/data.json?resource=%s", ip)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch ASN info: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch ASN info, status: %d", resp.StatusCode)
	}

	var ripestatResp RIPEstatResponse
	if err := json.NewDecoder(resp.Body).Decode(&ripestatResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	var asnDetails ASNDetails
	for _, recordGroup := range ripestatResp.Data.Records {
		for _, record := range recordGroup {
			switch record.Key {
			case "OriginAS":
				asnDetails.ASN = record.Value
			case "CIDR":
				asnDetails.Route = record.Value
			case "Organization":
				asnDetails.OrgName = record.Value
			}
		}
	}

	if asnDetails.ASN == "" && asnDetails.Route == "" && asnDetails.OrgName == "" {
		return nil, fmt.Errorf("no relevant ASN info found for IP: %s", ip)
	}

	return &asnDetails, nil
}
