FROM golang:1.21 as build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/ingest ./main.go

FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=build /out/ingest /app/ingest
EXPOSE 8081 9091
ENTRYPOINT ["/app/ingest"]
