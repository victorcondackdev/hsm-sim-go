# syntax=docker/dockerfile:1
FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/hsm-sim ./cmd/hsm-sim

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/hsm-sim /hsm-sim
EXPOSE 1500
ENTRYPOINT ["/hsm-sim", "-addr", ":1500"]
