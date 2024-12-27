GO := /opt/homebrew/bin/go

.DEFAULT_GOAL := help

help:
	@echo "Usage:"
	@echo "  make tidy          - Install dependencies"
	@echo "  make build         - Build the application"
	@echo "  make run_subdomain_report DOMAIN=example.com - Run subdomain report for the domain"
	@echo "  make run_get_dns_info DOMAIN=example.com    - Run DNS info retrieval for the domain"

tidy:
	$(GO) mod tidy

build:
	$(GO) build -o customer_search main.go

run_subdomain_report:
	$(GO) run main.go -action=subdomain_report -domain=$(DOMAIN)

run_get_dns_info:
	$(GO) run main.go -action=get_dns_info -domain=$(DOMAIN)
