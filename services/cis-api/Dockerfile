# CIS API (Go Fiber) — multi-stage build
# go.sum ถูก generate ตอน build ผ่าน `go mod tidy` (POC — production ควร commit go.sum)
# Central Auth SDK (packages/auth-go) มาผ่าน build context เพิ่ม (compose: additional_contexts.auth-go)
# และวางตาม path สัมพัทธ์ที่ go.mod ของ service ชี้ (replace ../../packages/auth-go)
FROM golang:1.24-alpine AS build
COPY --from=auth-go . /src/packages/auth-go/
WORKDIR /src/services/cis-api
ENV CGO_ENABLED=0
COPY go.mod ./
COPY . .
RUN go mod tidy
RUN go build -trimpath -ldflags="-s -w" -o /bin/cis-api .

FROM alpine:3.20
RUN adduser -D -u 10001 app
COPY --from=build /bin/cis-api /bin/cis-api
USER app
EXPOSE 3000
CMD ["/bin/cis-api"]
