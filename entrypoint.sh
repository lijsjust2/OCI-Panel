#!/bin/sh
# 启动时自动修正数据目录属主，再降权到 app 用户运行
# 解决 bind mount 宿主机目录属主为 root 导致的写入失败问题
set -e

DATA_DIR="${DATA_DIR:-/app/data}"

mkdir -p "$DATA_DIR"
# 数据目录属主改为容器内 app 用户（uid 1000）
chown -R app:app "$DATA_DIR" 2>/dev/null || echo "[启动] 警告: 无法修改 $DATA_DIR 属主，若写入失败请检查宿主机目录权限"

# 以 app 用户身份运行主程序
exec su-exec app:app oci-panel
