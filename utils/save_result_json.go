package utils

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

func SaveResult(domain string, jsonData []byte) string {
	resultDir := "result"
	if err := os.MkdirAll(resultDir, os.ModePerm); err != nil {
		log.Fatalf("Error creating result directory: %v", err)
	}

	timeStamp := time.Now().Format("20060102_150405")
	fileName := fmt.Sprintf("%s_%s.json", domain, timeStamp)
	filePath := filepath.Join(resultDir, fileName)

	if err := os.WriteFile(filePath, jsonData, 0644); err != nil {
		log.Fatalf("Error saving result file: %v", err)
	}

	return filePath
}
