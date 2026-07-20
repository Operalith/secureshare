FROM golang:1.23-alpine AS build

WORKDIR /src
RUN apk add --no-cache ca-certificates git

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -trimpath -ldflags="-s -w" -o /out/secureshare ./cmd/secureshare

FROM alpine:3.20

RUN apk add --no-cache ca-certificates wget \
    && addgroup -S secureshare \
    && adduser -S -G secureshare -h /app secureshare

WORKDIR /app
COPY --from=build /out/secureshare /usr/local/bin/secureshare
COPY migrations ./migrations
COPY docs ./docs
COPY web ./web

ENV TMPDIR=/tmp
USER secureshare
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/health/live >/dev/null || exit 1

ENTRYPOINT ["secureshare"]
