# Build and run:
#
#   docker build -t vandros-gateway .
#   docker volume create vandros-data
#   docker run -d --name vandros \
#     --restart unless-stopped --read-only --tmpfs /tmp --stop-timeout 15 \
#     -p 8080:8080 \
#     -e TZ -e VANDROS_SESSION_SECRET -e VANDROS_ADMIN_USER -e VANDROS_ADMIN_PASSWORD \
#     --user 10001:10001 \
#     -v "$PWD/config.yaml:/etc/vandros/config.yaml:ro" \
#     -v vandros-data:/var/lib/vandros \
#     -v /mnt/promise:/mnt/promise:ro \
#     vandros-gateway
#
# Add one -v for each host mount listed in config.yaml. The uid must already
# be able to read those paths. Vandros Gateway does not chown them.

FROM golang:1.27.2-alpine3.24 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/vandros .

FROM alpine:3.24.2

RUN apk add --no-cache tzdata \
    && addgroup -g 10001 -S vandros \
    && adduser -S -D -H -u 10001 -G vandros vandros \
    && mkdir -p /var/lib/vandros \
    && chown vandros:vandros /var/lib/vandros

COPY --from=build /out/vandros /usr/local/bin/vandros

USER vandros:vandros
ENV TZ=UTC
EXPOSE 8080
VOLUME ["/var/lib/vandros"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/vandros"]
CMD ["-config", "/etc/vandros/config.yaml"]
