# syntax=docker/dockerfile:1

FROM golang:1.25.11-alpine AS build-re2
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
COPY third_party ./third_party
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w -X github.com/openaudit/openaudit/internal/api.Version=${VERSION} -X github.com/openaudit/openaudit/internal/api.Commit=${COMMIT} -X github.com/openaudit/openaudit/internal/api.BuildTime=${BUILD_TIME}" \
    -o /out/openaudit ./cmd/server

FROM golang:1.25.11-alpine AS build-pcre2
WORKDIR /src
RUN apk add --no-cache ca-certificates build-base pkgconfig pcre2-dev
COPY go.mod go.sum ./
COPY third_party ./third_party
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown
RUN CGO_ENABLED=1 GOOS=linux go build -tags pcre2 \
    -ldflags "-s -w -X github.com/openaudit/openaudit/internal/api.Version=${VERSION} -X github.com/openaudit/openaudit/internal/api.Commit=${COMMIT} -X github.com/openaudit/openaudit/internal/api.BuildTime=${BUILD_TIME}" \
    -o /out/openaudit ./cmd/server

FROM alpine:3.20 AS default
WORKDIR /app
RUN apk add --no-cache ca-certificates && addgroup -S openaudit && adduser -S openaudit -G openaudit
COPY --from=build-re2 /out/openaudit /app/openaudit
COPY config.example.yml /app/config.yml
COPY data /app/data
RUN mkdir -p /app/storage && chown -R openaudit:openaudit /app
USER openaudit
EXPOSE 8080
ENTRYPOINT ["/app/openaudit"]
CMD ["--config", "/app/config.yml"]

FROM alpine:3.20 AS pcre2
WORKDIR /app
RUN apk add --no-cache ca-certificates pcre2 && addgroup -S openaudit && adduser -S openaudit -G openaudit
COPY --from=build-pcre2 /out/openaudit /app/openaudit
COPY config.example.yml /app/config.yml
COPY data /app/data
RUN mkdir -p /app/storage && chown -R openaudit:openaudit /app
USER openaudit
EXPOSE 8080
ENTRYPOINT ["/app/openaudit"]
CMD ["--config", "/app/config.yml"]
