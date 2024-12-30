package utils

import (
	"encoding/json"
	"fmt"
	"github.com/xuri/excelize/v2"
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

func ExportToExcel(inputFile string) (string, error) {
	file, err := os.Open(inputFile)
	if err != nil {
		return "", fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	var data Output
	if err := json.NewDecoder(file).Decode(&data); err != nil {
		return "", fmt.Errorf("error decoding JSON: %v", err)
	}

	excel := excelize.NewFile()
	sheetName := "Domain Data"
	excel.NewSheet(sheetName)

	headers := []string{"Domain", "Subdomain", "IP Addresses", "Reverse Lookup"}
	for i, header := range headers {
		col := string('A' + i)
		excel.SetCellValue(sheetName, col+"1", header)
	}

	row := 2
	for subdomain, ipDetail := range data.IPAddresses {
		excel.SetCellValue(sheetName, fmt.Sprintf("A%d", row), data.Domain)
		excel.SetCellValue(sheetName, fmt.Sprintf("B%d", row), subdomain)
		excel.SetCellValue(sheetName, fmt.Sprintf("C%d", row), fmt.Sprintf("%v", ipDetail.IPs))
		excel.SetCellValue(sheetName, fmt.Sprintf("D%d", row), fmt.Sprintf("%v", ipDetail.ReverseLookup))
		row++
	}

	outputFile := fmt.Sprintf("result/%s.xlsx", data.Domain)
	if err := excel.SaveAs(outputFile); err != nil {
		return "", fmt.Errorf("error saving Excel file: %v", err)
	}
	return outputFile, nil
}
