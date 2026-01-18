FROM golang:1.23 AS build
WORKDIR /src
COPY . ./
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/mcp-server ./main.go

FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=build /out/mcp-server /app/mcp-server
EXPOSE 8090
ENTRYPOINT ["/app/mcp-server"]
