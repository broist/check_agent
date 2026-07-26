# syntax=docker/dockerfile:1
FROM golang:1.26.5-alpine AS build
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_TIME=unknown
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN mkdir -p /out/data && CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X github.com/broist/check_agent/internal/version.Version=${VERSION} -X github.com/broist/check_agent/internal/version.Commit=${COMMIT} -X github.com/broist/check_agent/internal/version.BuildTime=${BUILD_TIME}" \
    -o /out/monitorozo-server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/monitorozo-server /monitorozo-server
COPY --chown=nonroot:nonroot --from=build /out/data /var/lib/monitorozo-server
USER nonroot:nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/monitorozo-server", "healthcheck", "http://127.0.0.1:8080/readyz"]
ENTRYPOINT ["/monitorozo-server"]
CMD ["-config", "/etc/monitorozo/server.yaml"]
