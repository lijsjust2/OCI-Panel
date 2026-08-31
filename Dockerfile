# 构建阶段
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/oci-panel .

# 运行阶段：alpine + su-exec（启动时自动修数据目录权限后降权运行）
FROM alpine:3.20
RUN adduser -D -u 1000 app && apk add --no-cache su-exec tzdata
WORKDIR /app
COPY --from=builder /out/oci-panel /usr/local/bin/oci-panel
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV PORT=8800 DATA_DIR=/app/data TZ=Asia/Shanghai
VOLUME /app/data
EXPOSE 8800
# 以 root 启动执行 entrypoint（仅用于 chown 数据目录），随后降权为 app 用户
ENTRYPOINT ["/entrypoint.sh"]
