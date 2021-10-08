// Package ipwhois is a command that queries IANA and other Network Information
// Centers for IP ownership by country.
package ipwhois // import "cirello.io/ipwhois"

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

// ErrAnswerNotFound means that query command was not able to find the line
// for the country in the returned responses. It can happen either because
// the IP is invalid, but also because the parser could have failed and
// you need to query further using other tools.
var ErrAnswerNotFound = errors.New("answer not found")

// Query reports what is the country owning the given IP. In-flight requests
// can be stopped if the given contenxt is canceled.
func Query(ctx context.Context, rawIP string) (string, error) {
	const ianaHost = "whois.iana.org"
	parsedIP := net.ParseIP(rawIP)
	if parsedIP == nil {
		return "", errors.New("query is not an IP")
	}
	ip := parsedIP.String()
	return recursiveQuery(ctx, ianaHost, ip)
}

func recursiveQuery(ctx context.Context, whoisHost, ip string) (string, error) {
	whoisResp, err := query(ctx, whoisHost, ip)
	if err != nil {
		return "", fmt.Errorf("cannot read %q response: %w", whoisHost, err)
	}
	var finalResponse string
	if foundReferral := grepInsensitiveFirstLine(whoisResp, "referralserver:"); foundReferral != "" {
		delegate := strings.TrimSpace(strings.TrimPrefix(foundReferral, "referralserver:"))
		referralResponse, err := recursiveQuery(ctx, delegate, ip)
		if err != nil {
			return "", fmt.Errorf("cannot read response of delegate %q: %w", delegate, err)
		}
		return referralResponse, nil
	} else if foundRedirect := grepInsensitiveFirstLine(whoisResp, "whois:"); foundRedirect != "" {
		delegate := strings.TrimSpace(strings.TrimPrefix(foundRedirect, "whois:"))
		redirectResponse, err := recursiveQuery(ctx, delegate, ip)
		if err != nil {
			return "", fmt.Errorf("cannot read response of delegate %q: %w", delegate, err)
		}
		return redirectResponse, nil
	} else if foundCountry := grepInsensitiveFirstLine(whoisResp, "country:"); foundCountry != "" {
		finalResponse = foundCountry
	}
	resp := strings.TrimSpace(strings.TrimPrefix(finalResponse, "country:"))
	if resp == "" {
		return "", ErrAnswerNotFound
	}
	return resp, nil
}

func query(ctx context.Context, whois, ip string) (string, error) {
	whois = strings.ReplaceAll(whois, "whois://", "")
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(whois, "43"))
	if err != nil {
		return "", fmt.Errorf("cannot talk to %q: %w", whois, err)
	}
	defer conn.Close()
	query := queryBuilder(whois, ip)
	if _, err := fmt.Fprint(&cancellableWriter{ctx, conn}, query, "\r\n"); err != nil {
		return "", fmt.Errorf("cannot write query to %q: %w", whois, err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&cancellableWriter{ctx, &buf}, conn); err != nil {
		return "", fmt.Errorf("cannot read target's response (%s): %w", whois, err)
	}
	return buf.String(), nil
}

func grepInsensitiveFirstLine(s, substr string) string {
	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() {
		line := strings.ToLower(scanner.Text()) + "\n"
		if strings.Contains(line, substr) {
			return line
		}
	}
	return ""
}

type cancellableWriter struct {
	ctx context.Context
	w   io.Writer
}

func (cw *cancellableWriter) Write(p []byte) (int, error) {
	select {
	case <-cw.ctx.Done():
		return 0, cw.ctx.Err()
	default:
		return cw.w.Write(p)
	}
}

func queryBuilder(target, ip string) string {
	switch target {
	case "whois.arin.net":
		return "+ " + ip
	default:
		return ip
	}
}
