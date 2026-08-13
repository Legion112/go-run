package nftables

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/legion/go-tun/internal/linux"
	"github.com/legion/go-tun/internal/policy"
)

// ElementBatchSize is how many CIDRs to put in each nft "add element" statement.
const ElementBatchSize = 4000

// largeSetThreshold: above this, semantic match uses JSON element count instead of per-CIDR Contains.
const largeSetThreshold = 1000

// Reconcile applies owned nftables table state with atomic set population.
// Returns number of semantic changes applied.
func Reconcile(r linux.Runner, spec policy.NftSpec) (int, error) {
	changes := 0
	family, table := spec.Family, spec.Table

	listed, err := r.Run("nft", "list", "table", family, table)
	tableExists := err == nil && listed != "" && !strings.Contains(listed, "Error")

	if tableExists && semanticMatch(r, listed, spec) {
		return 0, nil
	}

	script := RenderFullTable(spec)
	if tableExists {
		if _, err := r.Run("nft", "delete", "table", family, table); err != nil {
			return changes, err
		}
		changes++
	}
	if _, err := r.RunWithInput("nft", script, "-f", "-"); err != nil {
		return changes, fmt.Errorf("nft apply table: %w", err)
	}
	changes++
	return changes, nil
}

func semanticMatch(r linux.Runner, listed string, spec policy.NftSpec) bool {
	if !strings.Contains(listed, "table "+spec.Family+" "+spec.Table) && !strings.Contains(listed, "table inet gotun") {
		return false
	}
	if !strings.Contains(listed, "mark-non-direct") && !strings.Contains(listed, "meta mark set") {
		return false
	}
	for _, set := range spec.Sets {
		if !strings.Contains(listed, set.Name) {
			return false
		}
		if len(set.Elements) > largeSetThreshold {
			n, err := CountSetElements(r, spec.Family, spec.Table, set.Name)
			if err != nil || n != len(set.Elements) {
				return false
			}
			continue
		}
		for _, el := range set.Elements {
			if !strings.Contains(listed, el.String()) {
				return false
			}
		}
	}
	return true
}

// RenderFullTable builds an nft -f script for the owned table (batched add element).
func RenderFullTable(spec policy.NftSpec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "add table %s %s\n", spec.Family, spec.Table)
	for _, set := range spec.Sets {
		fmt.Fprintf(&b, "add set %s %s %s { type %s; flags interval; }\n", spec.Family, spec.Table, set.Name, set.Type)
		writeBatchedElements(&b, spec.Family, spec.Table, set.Name, prefixesToStrings(set))
	}
	for _, chain := range spec.Chains {
		fmt.Fprintf(&b, "add chain %s %s %s { type %s hook %s priority %d; policy %s; }\n",
			spec.Family, spec.Table, chain.Name, chain.Type, chain.Hook, chain.Priority, chain.Policy)
		for _, line := range renderRuleLines(chain) {
			fmt.Fprintf(&b, "add rule %s %s %s %s\n", spec.Family, spec.Table, chain.Name, line)
		}
	}
	return b.String()
}

func prefixesToStrings(set policy.NftSetSpec) []string {
	out := make([]string, len(set.Elements))
	for i, el := range set.Elements {
		out[i] = el.String()
	}
	return out
}

func writeBatchedElements(b *strings.Builder, family, table, setName string, elements []string) {
	for i := 0; i < len(elements); i += ElementBatchSize {
		end := i + ElementBatchSize
		if end > len(elements) {
			end = len(elements)
		}
		batch := elements[i:end]
		fmt.Fprintf(b, "add element %s %s %s { %s }\n", family, table, setName, strings.Join(batch, ", "))
	}
}

func renderRuleLines(chain policy.NftChainSpec) []string {
	var lines []string
	for _, rule := range chain.Rules {
		switch {
		case rule.DropIPv6:
			lines = append(lines, `meta nfproto ipv6 drop comment "drop-ipv6"`)
		case rule.Description == "mark-non-direct":
			for _, p := range rule.ExcludePrefixes {
				lines = append(lines, fmt.Sprintf(`ip daddr %s return comment "exclude-lan"`, p.String()))
			}
			for _, a := range rule.ExcludeAddrs {
				lines = append(lines, fmt.Sprintf(`ip daddr %s return comment "exclude-endpoint"`, a.String()))
			}
			lines = append(lines, fmt.Sprintf(`ip daddr != @%s meta mark set 0x%x comment "mark-non-direct"`, rule.DirectSet, rule.Mark))
		}
	}
	return lines
}

// SwapSetElements builds a new set, populates it in batches, and replaces live contents via nft -f.
func SwapSetElements(r linux.Runner, family, table, liveName string, elements []string) (int, error) {
	tmp := liveName + "_new"
	var b strings.Builder
	fmt.Fprintf(&b, "delete set %s %s %s\n", family, table, tmp)
	fmt.Fprintf(&b, "add set %s %s %s { type ipv4_addr; flags interval; }\n", family, table, tmp)
	writeBatchedElements(&b, family, table, tmp, elements)
	fmt.Fprintf(&b, "flush set %s %s %s\n", family, table, liveName)
	writeBatchedElements(&b, family, table, liveName, elements)
	fmt.Fprintf(&b, "delete set %s %s %s\n", family, table, tmp)
	if _, err := r.RunWithInput("nft", b.String(), "-f", "-"); err != nil {
		return 0, err
	}
	return 1, nil
}

// CountSetElements returns the number of elements in an nft set via nft -j.
func CountSetElements(r linux.Runner, family, table, setName string) (int, error) {
	out, err := r.Run("nft", "-j", "list", "set", family, table, setName)
	if err != nil {
		return 0, err
	}
	return countElementsJSON(out)
}

func countElementsJSON(out string) (int, error) {
	var root struct {
		Nftables []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &root); err != nil {
		// Fallback: count "prefix" / CIDR-like tokens in non-JSON list output.
		return strings.Count(out, "/"), fmt.Errorf("nft json: %w", err)
	}
	n := 0
	for _, raw := range root.Nftables {
		var wrap map[string]json.RawMessage
		if err := json.Unmarshal(raw, &wrap); err != nil {
			continue
		}
		setRaw, ok := wrap["set"]
		if !ok {
			continue
		}
		var setObj struct {
			Elem []json.RawMessage `json:"elem"`
		}
		if err := json.Unmarshal(setRaw, &setObj); err != nil {
			continue
		}
		n += len(setObj.Elem)
	}
	return n, nil
}

// Clear removes the owned table.
func Clear(r linux.Runner, family, table string) error {
	_, err := r.Run("nft", "delete", "table", family, table)
	if err != nil && strings.Contains(err.Error(), "No such file") {
		return nil
	}
	if err != nil && strings.Contains(err.Error(), "does not exist") {
		return nil
	}
	return err
}
