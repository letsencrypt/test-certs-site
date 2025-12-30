FROM golang:1.25.3-bookworm AS build

WORKDIR /src

COPY go.mod .
COPY go.sum .

RUN --mount=type=cache,id=gomod,target=/go/pkg/mod \
    go mod download

COPY . .

ENV CGO_ENABLED=0

RUN --mount=type=cache,id=gomod,target=/go/pkg/mod \
    --mount=type=cache,id=gobuild,target=/root/.cache/go-build \
    go install .

FROM debian:bookworm-slim

COPY --from=build /go/bin/test-certs-site /test-certs-site

RUN mkdir /data && chown 10001:10001 /data

USER 10001

CMD ["/test-certs-site", "-config", "/test-certs-site-config.json"]
