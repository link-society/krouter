##############################
## SOURCE FILES
##############################

FROM scratch AS sources

ADD go.mod go.su[m] /src/
ADD cmd /src/cmd
ADD internal /src/internal

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
    go build -trimpath -ldflags="-s -w" -o bin/ ./cmd/...

##############################
## FINAL ARTIFACT
##############################

FROM scratch AS runner

COPY --from=builder-go /workspace/bin/krouter /usr/local/bin/krouter

USER 10001:10001

ENV KROUTER_MODE=""
ENV KROUTER_CONTROLLER_NAME="link-society.com/krouter"
ENV KROUTER_SYSTEM_NAMESPACE="krouter-system"
ENV KROUTER_LOG_LEVEL="info"

ENV KROUTER_INTERNAL_PORT_MIN="10000"
ENV KROUTER_INTERNAL_PORT_MAX="29999"

ENV KROUTER_MANAGEMENT_PORT="9090"

ENTRYPOINT ["/usr/local/bin/krouter"]
CMD []
