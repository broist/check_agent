# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_TIME=unknown
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X github.com/broist/check_agent/internal/version.Version=${VERSION} -X github.com/broist/check_agent/internal/version.Commit=${COMMIT} -X github.com/broist/check_agent/internal/version.BuildTime=${BUILD_TIME}" \
    -o /out/monitorozo-server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/monitorozo-server /monitorozo-server
USER nonroot:nonroot
ENTRYPOINT ["/monitorozo-server"]
CMD ["-config", "/etc/monitorozo/server.yaml"]

