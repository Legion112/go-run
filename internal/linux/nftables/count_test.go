package nftables

import "testing"

func TestCountElementsJSON(t *testing.T) {
	out := `{"nftables":[{"metainfo":{"version":"1"}},{"set":{"family":"inet","name":"ru_nets","table":"gotun","elem":["1.2.3.0/24","5.6.7.0/24","8.9.0.0/16"]}}]}`
	n, err := countElementsJSON(out)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("got %d want 3", n)
	}
}
