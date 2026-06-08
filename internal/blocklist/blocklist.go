package blocklist

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
)

const defaultHTTPTimeout = 10 * time.Second

// LoadRules reads node-side blocklist sources and converts them to structured
// block route rules. It is intentionally limited to line-based lists such as
// Rakau/blockList, where comments start with # and each non-empty line is a
// domain suffix, keyword, or IP CIDR.
func LoadRules(ctx context.Context, cfg config.BlockListConfig) ([]model.CustomRouteRule, error) {
	if !cfg.EffectiveEnabled() {
		return nil, nil
	}

	var parsed parsedList
	if path := strings.TrimSpace(cfg.Path); path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open blocklist path %q: %w", path, err)
		}
		if err := parsed.read(f); err != nil {
			f.Close()
			return nil, fmt.Errorf("parse blocklist path %q: %w", path, err)
		}
		if err := f.Close(); err != nil {
			return nil, fmt.Errorf("close blocklist path %q: %w", path, err)
		}
	}

	if url := strings.TrimSpace(cfg.URL); url != "" {
		if err := parsed.readURL(ctx, url); err != nil {
			return nil, err
		}
	}

	rule := parsed.rule()
	if !hasRouteMatch(rule.Match) {
		return nil, nil
	}
	return []model.CustomRouteRule{rule}, nil
}

type parsedList struct {
	domainKeywords map[string]struct{}
	domains        map[string]struct{}
	domainSuffixes map[string]struct{}
	ipcidrs        map[string]struct{}
}

func (p *parsedList) read(r io.Reader) error {
	p.ensure()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		p.addLine(scanner.Text())
	}
	return scanner.Err()
}

func (p *parsedList) readURL(ctx context.Context, url string) error {
	reqCtx, cancel := context.WithTimeout(ctx, defaultHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create blocklist request %q: %w", url, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch blocklist url %q: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("fetch blocklist url %q: unexpected status %s", url, resp.Status)
	}
	if err := p.read(resp.Body); err != nil {
		return fmt.Errorf("parse blocklist url %q: %w", url, err)
	}
	return nil
}

func (p *parsedList) ensure() {
	if p.domainKeywords == nil {
		p.domainKeywords = make(map[string]struct{})
		p.domains = make(map[string]struct{})
		p.domainSuffixes = make(map[string]struct{})
		p.ipcidrs = make(map[string]struct{})
	}
}

func (p *parsedList) addLine(line string) {
	line = strings.TrimPrefix(line, "\ufeff")
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	value := normalizeEntry(line)
	if value == "" {
		return
	}
	if strings.ContainsAny(value, " \t\r\n") {
		return
	}
	if _, err := netip.ParsePrefix(value); err == nil {
		p.ipcidrs[value] = struct{}{}
		return
	}
	if strings.HasPrefix(value, "geoip:") {
		p.ipcidrs[value] = struct{}{}
		return
	}
	if strings.HasPrefix(value, "geosite:") {
		p.domains[value] = struct{}{}
		return
	}
	if strings.Contains(value, ".") {
		p.domainSuffixes[value] = struct{}{}
		return
	}
	p.domainKeywords[value] = struct{}{}
}

func normalizeEntry(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "domain:")
	value = strings.TrimPrefix(value, "full:")
	value = strings.TrimPrefix(value, "*.")
	value = strings.TrimPrefix(value, ".")
	return strings.TrimSuffix(value, ".")
}

func (p *parsedList) rule() model.CustomRouteRule {
	return model.CustomRouteRule{
		Name: "node-blocklist",
		Match: model.RouteMatch{
			DomainKeywords: sortedKeys(p.domainKeywords),
			Domains:        sortedKeys(p.domains),
			DomainSuffixes: sortedKeys(p.domainSuffixes),
			IPCIDRs:        sortedKeys(p.ipcidrs),
		},
		Action: model.RouteAction{Type: "block"},
	}
}

func sortedKeys(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func hasRouteMatch(match model.RouteMatch) bool {
	return len(match.DomainKeywords) > 0 || len(match.Domains) > 0 || len(match.DomainSuffixes) > 0 || len(match.IPCIDRs) > 0
}
