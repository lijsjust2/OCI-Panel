# 构建阶段
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/oci-panel .

# 运行阶段：scratch 或 alpine（alpine 便于排查）
FROM alpine:3.20
RUN adduser -D -u 1000 app && mkdir -p /app/data && chown -R app:app /app/data
WORKDIR /app
COPY --from=builder /out/oci-panel /usr/local/bin/oci-panel
USER app
ENV PORT=8800 DATA_DIR=/app/data
VOLUME /app/data
EXPOSE 8800
ENTRYPOINT ["oci-panel"]
