##############################
## SOURCE FILES
##############################

FROM scratch AS sources

ADD tests/mocks/go.mod tests/mocks/go.su[m] /src/
ADD tests/mocks/cmd /src/cmd

##############################
## BUILD GO CODE
##############################

FROM golang:1.26-alpine3.22 AS builder-go
ARG TARGETOS
ARG TARGETARCH

RUN mkdir -p /workspace
WORKDIR /workspace

COPY --from=sources /src/go.mod /src/go.su[m] ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY --from=sources /src /workspace

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o bin/grpcbin ./cmd/grpcbin

##############################
## FINAL ARTIFACT
##############################

FROM scratch AS runner

COPY --from=builder-go /workspace/bin/grpcbin /usr/local/bin/grpcbin

USER 10001:10001

ENV PORT="9000"
ENV TLS_PORT="9001"
ENV TLS_SERVER_NAMES=""

ENTRYPOINT ["/usr/local/bin/grpcbin"]
