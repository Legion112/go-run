GO ?= go
BIN := bin/gotun
BIN_DNS := bin/gotun-dns
MMDB := data/geo/GeoIP2-City.mmdb

.PHONY: all build test test-integration test-large-set docker-build fetch-prefixes clean

all: build test

build:
	mkdir -p bin
	$(GO) build -o $(BIN) ./cmd/gotun
	$(GO) build -o $(BIN_DNS) ./cmd/gotun-dns

test:
	$(GO) test ./...

test-integration: docker-build
	GOTUN_INTEGRATION=1 $(GO) test -tags=integration -count=1 -timeout 10m ./test/integration/...

test-large-set: docker-build
	GOTUN_LARGE_SET=1 $(GO) test -count=1 -timeout 20m ./internal/linux/nftables/ -run 'LargeRUSet'

docker-build:
	docker build -t gotun:lab .

fetch-prefixes: build
	@if [ -f "$(MMDB)" ]; then \
		$(BIN) fetch -mmdb "$(MMDB)" -out prefixes.txt; \
	else \
		echo "No local MMDB at $(MMDB); using MaxMind CSV download (MAXMIND_LICENSE_KEY required)"; \
		$(BIN) fetch -out prefixes.txt; \
	fi

clean:
	rm -rf bin/
