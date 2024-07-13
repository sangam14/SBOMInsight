# Stage 1: Build the binary
FROM golang:1.22-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o sbominsight .
FROM alpine:latest
WORKDIR /root/
COPY --from=build /app/sbominsight .
ENTRYPOINT ["./sbominsight"]