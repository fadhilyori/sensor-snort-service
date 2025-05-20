ARG GO_VERSION=1.23

FROM golang:${GO_VERSION}-alpine AS build

ARG APP_NAME="me-sensor-service"
ARG APP_VERSION="dev"
ARG APP_COMMIT="none"

RUN apk add --no-cache librdkafka-dev pkgconf build-base musl-dev

WORKDIR /go/src/app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

ENV CGO_ENABLED=1
ENV GOOS=linux
ENV GO111MODULE=on

RUN go build -ldflags "-X main.appVersion=${APP_VERSION} -X main.appCommit=${APP_COMMIT} -X main.appLicense=${APP_LICENSE}" -tags dynamic -tags musl -o /go/bin/app ./cmd/

FROM golang:${GO_VERSION}-alpine

RUN adduser -D -u 1000 appuser && \
    mkdir -p /go/bin && \
    chown -R appuser:appuser /go/bin

COPY --from=build --chown=appuser:appuser /go/bin/app /go/bin/app

RUN apk add --no-cache librdkafka

USER appuser

ENTRYPOINT ["/go/bin/app"]
