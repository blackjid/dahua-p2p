FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build
ARG TARGETOS TARGETARCH

WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/dahua-p2p ./cmd/dahua-p2p

FROM scratch
COPY --from=build /out/dahua-p2p /dahua-p2p
USER 65532:65532
EXPOSE 8554
ENTRYPOINT ["/dahua-p2p"]
