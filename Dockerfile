FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY . .
RUN CGO_ENABLED=0 go build -o /gotun ./cmd/gotun \
 && CGO_ENABLED=0 go build -o /gotun-dns ./cmd/gotun-dns \
 && CGO_ENABLED=0 go build -o /labhttp ./cmd/labhttp \
 && CGO_ENABLED=0 go build -o /labdns ./cmd/labdns

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables wireguard-tools iproute2 iputils-ping curl ca-certificates \
    procps dnsutils \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /gotun /usr/local/bin/gotun
COPY --from=build /gotun-dns /usr/local/bin/gotun-dns
COPY --from=build /labhttp /usr/local/bin/labhttp
COPY --from=build /labdns /usr/local/bin/labdns
ENTRYPOINT ["sleep", "infinity"]
