// OCI Panel（Go 版）入口：初始化存储 → 启动定时任务 → 启动 HTTP 服务
package main

import (
	"log"
	"net/http"
	"time"

	"oci-panel/internal/config"
	"oci-panel/internal/scheduler"
	"oci-panel/internal/store"
	"oci-panel/internal/web"
)

func main() {
	store.Init()
	scheduler.Start()

	srv := &http.Server{
		Addr:              ":" + config.Port,
		Handler:           web.New(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("OCI Panel (Go) 已启动，监听端口 %s，数据目录 %s", config.Port, config.DataDir)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP 服务启动失败: %v", err)
	}
}
