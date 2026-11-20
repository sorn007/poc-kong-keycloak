# ID Portal (Go Fiber) — multi-stage build
# go.sum ถูก generate ตอน build ผ่าน `go mod tidy` (POC — production ควร commit go.sum)
FROM golang:1.24-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY go.mod ./
COPY . .
RUN go mod tidy
RUN go build -trimpath -ldflags="-s -w" -o /bin/central-id .

FROM alpine:3.20
RUN adduser -D -u 10001 app
COPY --from=build /bin/central-id /bin/central-id
USER app
EXPOSE 3000
CMD ["/bin/central-id"]
