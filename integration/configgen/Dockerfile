FROM golang:1.26.1-trixie AS build

WORKDIR /src

COPY go.mod .
COPY go.sum .

RUN --mount=type=cache,id=gomod,target=/go/pkg/mod \
    go mod download

COPY . .

ENV CGO_ENABLED=0

RUN --mount=type=cache,id=gomod,target=/go/pkg/mod \
    --mount=type=cache,id=gobuild,target=/root/.cache/go-build \
    go build -o /go/bin/configgen ./integration/configgen

FROM debian:trixie-slim

COPY --from=build /go/bin/configgen /configgen

ENTRYPOINT ["/configgen"]
