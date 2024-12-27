package virustotal

import (
	"customer_research/utils"
	"encoding/json"
	"fmt"
	"net/http"
)

type DomainInfo struct {
	ID          string           `json:"id"`
	Whois       string           `json:"whois"`
	TLD         string           `json:"tld"`
	DNSRecords  []DNSRecord      `json:"last_dns_records"`
	Certificate HTTPSCertificate `json:"last_https_certificate"`
}

type DNSRecord struct {
	Type     string  `json:"type"`
	TTL      int     `json:"ttl"`
	Value    string  `json:"value"`
	Priority *int    `json:"priority,omitempty"`
	RName    *string `json:"rname,omitempty"`
	Serial   *int    `json:"serial,omitempty"`
	Refresh  *int    `json:"refresh,omitempty"`
	Retry    *int    `json:"retry,omitempty"`
	Expire   *int    `json:"expire,omitempty"`
	Minimum  *int    `json:"minimum,omitempty"`
}

type HTTPSCertificate struct {
	Extensions       CertExtensions `json:"extensions"`
	Issuer           CertEntity     `json:"issuer"`
	Subject          CertEntity     `json:"subject"`
	Thumbprint       string         `json:"thumbprint"`
	ThumbprintSHA256 string         `json:"thumbprint_sha256"`
	Version          string         `json:"version"`
	SerialNumber     string         `json:"serial_number"`
}

type CertExtensions struct {
	SubjectAlternativeNames []string          `json:"subject_alternative_name"`
	KeyUsage                []string          `json:"key_usage"`
	ExtendedKeyUsage        []string          `json:"extended_key_usage"`
	CAInformationAccess     map[string]string `json:"ca_information_access"`
}

type CertEntity struct {
	CN string `json:"CN"`
	O  string `json:"O"`
	C  string `json:"C"`
}

func GetDomainInfo(domain, apiKey string) (*DomainInfo, error) {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", domain)

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
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var data struct {
		Data struct {
			Attributes DomainInfo `json:"attributes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return &data.Data.Attributes, nil
}
