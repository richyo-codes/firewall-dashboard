FROM node:22-alpine AS ui-build
WORKDIR /app/ui
COPY ui/package*.json ./
RUN npm ci
COPY ui/ .
RUN npm run build

FROM golang:1.25-alpine AS base
WORKDIR /app
COPY go.mod go.sum ./
RUN apk add --no-cache just && go mod download
COPY . .
COPY --from=ui-build /app/ui/dist ./ui/dist

FROM base AS test
RUN just test

FROM base AS build
RUN just build

FROM alpine:3.23 AS release
RUN adduser -D appuser
WORKDIR /app
COPY --from=build /app/pf-dashboard .
USER appuser
EXPOSE 8080
ENTRYPOINT ["./pf-dashboard"]
