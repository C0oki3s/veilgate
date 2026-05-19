# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/veilgate ./cmd/veilgate

FROM alpine:3.22
RUN apk add --no-cache ca-certificates && \
    mkdir -p /home/nonroot/.veilgate/rules /etc/veilgate
COPY --from=build /out/veilgate /veilgate
COPY configs/veilgate.yaml /etc/veilgate/veilgate.yaml
ENV HOME=/home/nonroot
EXPOSE 8080 9090
ENTRYPOINT ["/veilgate"]
CMD ["-config", "/etc/veilgate/veilgate.yaml"]
