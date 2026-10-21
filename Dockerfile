# Published image, built from main:
#   ghcr.io/tyesamson/vandros-gateway:latest
#
# The copy-paste run is in the README. Same command:
#
#   docker run --restart=unless-stopped -d \
#     --name vandros \
#     --read-only --tmpfs /tmp --stop-timeout 15 \
#     --user 10001:10001 \
#     -p 24731:24731 \
#     -v /etc/localtime:/etc/localtime:ro \
#     -v /mnt/docker/vandros-gateway/config.yaml:/etc/vandros/config.yaml:ro \
#     -v /mnt/docker/vandros-gateway/data:/var/lib/vandros \
#     -v /mnt/promise:/mnt/promise:ro \
#     -e TZ="Pacific/Auckland" \
#     -e VANDROS_SESSION_SECRET -e VANDROS_ADMIN_USER -e VANDROS_ADMIN_PASSWORD \
#     ghcr.io/tyesamson/vandros-gateway:latest
#
# Add one -v for each host mount listed in config.yaml. The path inside the
# container is the path in the config. uid 10001 must already be able to read
# those directories. Vandros Gateway leaves their ownership alone. The data
# directory has to be writable by uid 10001.

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
EXPOSE 24731
VOLUME ["/var/lib/vandros"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD wget -q -O /dev/null http://127.0.0.1:24731/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/vandros"]
CMD ["-config", "/etc/vandros/config.yaml"]
