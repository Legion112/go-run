package dnsproxy

// Path selects which upstream egress policy to use for a query.
type Path int

const (
	// PathDirect resolves without the tunnel (RU-side perspective).
	PathDirect Path = iota
	// PathExit resolves via the WireGuard exit hop (SO_MARK).
	PathExit
)

func (p Path) String() string {
	switch p {
	case PathDirect:
		return "direct"
	case PathExit:
		return "exit"
	default:
		return "unknown"
	}
}

// Classifier decides Direct vs Exit for a DNS question name.
type Classifier interface {
	Classify(name string) Path
}
