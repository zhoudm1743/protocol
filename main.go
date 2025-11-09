package main

import (
	"protocol/pkg/eventbus"
	"protocol/pkg/logger"
	"protocol/pkg/sse"
	"protocol/routes"

	"github.com/gin-gonic/gin"
)

func main() {
	// 初始化日志
	logger.Init()
	// 初始化事件总线
	bus := eventbus.GetDefaultBus()
	// 初始化SSE管理器
	manager := sse.NewSSEManager(bus)
	manager.Start()
	// 初始化路由
	r := gin.Default()
	routes.InitRoutes(r)
	// 启动服务器
	if err := r.Run(":8080"); err != nil {
		logger.Errorf("Failed to start server: %v", err)
		return
	}
}
