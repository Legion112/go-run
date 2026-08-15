package dnsproxy

import (
	"testing"
)

func TestSuffixClassifier(t *testing.T) {
	c := DefaultRUClassifier()
	direct := []string{
		"YANDEX.RU.",
		"yandex.ru",
		"foo.yandex.ru.",
		"ru.",
		"ru",
		"lavka.yandex.ru.",
	}
	for _, n := range direct {
		if got := c.Classify(n); got != PathDirect {
			t.Errorf("Classify(%q)=%s want direct", n, got)
		}
	}
	exit := []string{
		"notaru.com.",
		"example.ru.example.com.",
		"foo.ru.com.",
		"example.com.",
		"notru",
		"prus.ru.com",
	}
	for _, n := range exit {
		if got := c.Classify(n); got != PathExit {
			t.Errorf("Classify(%q)=%s want exit", n, got)
		}
	}
}
