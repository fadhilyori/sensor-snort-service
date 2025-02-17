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

#RUN go build -ldflags "-X main.appVersion=${APP_VERSION} -X main.appCommit=${APP_COMMIT} -X main.appLicense=${APP_LICENSE}" -tags dynamic -tags musl -o /go/bin/app ./cmd/me-sensor
#
#FROM golang:${GO_VERSION}-alpine
#
#RUN apk add --no-cache librdkafka
#
#COPY --from=build /go/bin/app /go/bin/app
#
#ENTRYPOINT ["/go/bin/app"]

RUN apk add --no-cache librdkafka curl && \
    addgroup -g 1001 -S snort && \
    adduser -S -u 1001 -G snort snort ; \
    mkdir -p /var/log/snort ; \
    install -g snort -o snort -m 5775 -d /var/log/snort

HEALTHCHECK --interval=5s --timeout=3s --retries=3 CMD curl -f http://localhost:9101/metrics || exit 1

RUN go build -ldflags "-X main.appVersion=${APP_VERSION} -X main.appCommit=${APP_COMMIT} -X main.appLicense=${APP_LICENSE}" -tags dynamic -tags musl -o /go/bin/app ./cmd/testing

USER snort

ENTRYPOINT ["/go/bin/app"]
