FROM node:20-alpine AS ui-build
WORKDIR /app/ui
COPY ui/package*.json ./
RUN npm install
COPY ui/ .
RUN npm run build

FROM golang:1.22-alpine AS base
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui-build /app/ui/dist ./ui/dist

FROM base AS test
RUN go test ./...

FROM base AS build
RUN GOOS=linux GOARCH=amd64 go build -o pf-dashboard

FROM alpine:3.20 AS release
RUN adduser -D appuser
WORKDIR /app
COPY --from=build /app/pf-dashboard .
USER appuser
EXPOSE 8080
ENTRYPOINT ["./pf-dashboard"]
