I initiated this project to gather IT service-related data for customers, particularly focusing on domain and network information. The project primarily leverages the **VirusTotal API** to retrieve data, with plans to integrate additional tools and services in the future. Note that I created this project solely for personal purposes, so I filter out many arguments according to my intentions.

# Features:
* Retrieve detailed information about a domain, including its DNS and certificate data.
  * Get ASN Information from **RIPEstat**. Note that, if the data retrived does not contain "CIDR", "OriginAS", and "Organization", it may not be displayed in the result.
* Identify subdomains for a given domain, along with their associated IP addresses and reverse lookup results.