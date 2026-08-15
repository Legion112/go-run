package dnsproxy

import (
	"strings"

	"codeberg.org/miekg/dns/dnsutil"
)

// SuffixClassifier sends names matching DirectSuffixes (e.g. ".ru") via PathDirect.
type SuffixClassifier struct {
	DirectSuffixes []string
}

// Classify implements Classifier. Names are lowercased and FQDN-normalized.
func (c SuffixClassifier) Classify(name string) Path {
	n := dnsutil.Canonical(strings.TrimSpace(name))
	for _, suf := range c.DirectSuffixes {
		s := dnsutil.Canonical(strings.TrimSpace(suf))
		// Allow configuring either ".ru" or "ru".
		if !strings.HasPrefix(s, ".") {
			s = "." + s
		}
		if n == strings.TrimPrefix(s, ".") {
			return PathDirect
		}
		if strings.HasSuffix(n, s) {
			return PathDirect
		}
	}
	return PathExit
}

// DefaultRUClassifier returns SuffixClassifier for .ru (v1 CLI default).
func DefaultRUClassifier() Classifier {
	return SuffixClassifier{DirectSuffixes: []string{".ru"}}
}
