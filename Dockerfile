FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY . .
RUN CGO_ENABLED=0 go build -o /gotun ./cmd/gotun \
 && CGO_ENABLED=0 go build -o /labhttp ./cmd/labhttp

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables wireguard-tools iproute2 iputils-ping curl ca-certificates \
    procps \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /gotun /usr/local/bin/gotun
COPY --from=build /labhttp /usr/local/bin/labhttp
ENTRYPOINT ["sleep", "infinity"]
