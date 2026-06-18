# syntax=docker/dockerfile:1

FROM golang:1.25.11-alpine AS build
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

FROM alpine:3.20
WORKDIR /app
RUN apk add --no-cache ca-certificates && addgroup -S openaudit && adduser -S openaudit -G openaudit
COPY --from=build /out/openaudit /app/openaudit
COPY config.example.yml /app/config.yml
COPY data /app/data
RUN mkdir -p /app/storage && chown -R openaudit:openaudit /app
USER openaudit
EXPOSE 8080
ENTRYPOINT ["/app/openaudit"]
CMD ["--config", "/app/config.yml"]
