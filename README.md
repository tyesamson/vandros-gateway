# Vandros Gateway

A self-hosted window onto directories on the host. It lists and downloads the files that are already there. It does not index them.

The image is built from `main` and published to `ghcr.io/tyesamson/vandros-gateway:latest`. The same push also tags the image with the full commit SHA.

## Run

Copy `config.example.yaml` to `config.yaml` and point each mount at a real directory. The path in the config is the path inside the container, and uid 10001 has to be able to read it. Vandros Gateway does not change ownership of those directories.

```sh
export VANDROS_SESSION_SECRET='at least 32 characters'
export VANDROS_ADMIN_USER=admin
export VANDROS_ADMIN_PASSWORD='choose one for the first start'
./scripts/run.sh
```

`scripts/run.sh` pulls `ghcr.io/tyesamson/vandros-gateway:latest`, mounts each configured directory read-only, and starts a read-only container named `vandros`. The database is the `vandros-data` volume.

`VANDROS_ADMIN_USER` and `VANDROS_ADMIN_PASSWORD` are used only while that volume has no users. Later starts ignore them.

Leave `session.secure` false while the portal is plain HTTP. Set it true when a proxy terminates HTTPS. To publish on one LAN address:

```sh
VANDROS_PUBLISH=192.168.20.112:8080:8080 ./scripts/run.sh
```

The environment variables, the mount rules, and the session setting are documented in `config.example.yaml`. The same `docker run` is in the Dockerfile comment.
