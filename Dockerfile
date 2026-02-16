FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o nocturne ./cmd/nocturne
RUN CGO_ENABLED=0 go build -o nocturne-node ./cmd/nocturne-node
RUN CGO_ENABLED=0 go build -o nocturne-agent ./cmd/nocturne-agent

FROM alpine:3.19
RUN apk add --no-cache ca-certificates && mkdir -p /data
WORKDIR /app
COPY --from=builder /app/nocturne .
COPY --from=builder /app/nocturne-node .
COPY --from=builder /app/nocturne-agent .
EXPOSE 8080
CMD ["./nocturne"]
