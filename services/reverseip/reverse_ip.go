package reverseip

import (
	"fmt"
	"net"
)

func GetReverseIP(host string) ([]string, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	var reversed []string
	for _, ip := range ips {
		names, err := net.LookupAddr(ip.String())
		if err != nil {
			return nil, fmt.Errorf("reverse lookup failed for IP: %s", ip.String())
		}
		reversed = append(reversed, names...)
	}

	return reversed, nil
}
