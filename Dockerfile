# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/veilgate ./cmd/veilgate

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/veilgate /veilgate
COPY configs/veilgate.yaml /etc/veilgate/veilgate.yaml
EXPOSE 8080 9090
USER nonroot:nonroot
ENTRYPOINT ["/veilgate"]
CMD ["-config", "/etc/veilgate/veilgate.yaml"]
