package config

import (
	"bufio"
	"os"
	"strings"
)

type Config struct {
	VirusTotalAPIKey string
}

func LoadConfig() (*Config, error) {
	file, err := os.Open(".config")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var apiKey string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == "VIRUSTOTAL_API_KEY" {
			apiKey = strings.TrimSpace(parts[1])
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if apiKey == "" {
		return nil, err
	}

	return &Config{VirusTotalAPIKey: apiKey}, nil
}
