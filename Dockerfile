# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/veilgate ./cmd/veilgate

# Pre-create the rules directory owned by nonroot (uid 65532).
# Distroless has no shell, so we create directory structure here and copy it
# into the final stage. The ML miner writes learned.yaml to this path on
# every tick; without it the miner silently fails with "read-only file system".
# When operators mount a volume over this path they must NOT use :ro —
# see docs/deployment/README.md for the correct Docker run flags.
RUN mkdir -p /home/nonroot/.veilgate/rules && \
    chown -R 65532:65532 /home/nonroot/.veilgate

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/veilgate /veilgate
COPY --from=build --chown=65532:65532 /home/nonroot/.veilgate /home/nonroot/.veilgate
COPY configs/veilgate.yaml /etc/veilgate/veilgate.yaml
ENV HOME=/home/nonroot
EXPOSE 8080 9090
USER nonroot:nonroot
ENTRYPOINT ["/veilgate"]
CMD ["-config", "/etc/veilgate/veilgate.yaml"]
