package routes

import (
	"context"
	"encoding/json"
	"protocol/app/controller"
	"protocol/pkg/eventbus"
	"protocol/pkg/logger"
	"protocol/pkg/sse"

	"github.com/gin-gonic/gin"
)

func InitRoutes(r *gin.Engine) {
	// 静态文件服务 - webapp 目录映射到根路径
	// 这样 HTML 中的相对路径（如 ./lib/layui/layui.js）可以正常工作
	r.Static("/lib", "./webapp/lib")
	r.Static("/images", "./webapp/images")
	r.Static("/pages", "./webapp/pages")
	r.Static("/scripts", "./webapp/scripts")
	r.Static("/styles", "./webapp/styles")

	// 主页
	r.StaticFile("/", "./webapp/index.html")

	// API 路由组
	api := r.Group("/api")
	{
		// CJ188 协议路由
		cj188 := api.Group("/cj188")
		{
			cj188.POST("/parse", controller.ParseCj188)                        // 解析协议帧
			cj188.POST("/build", controller.BuildCj188)                        // 构建协议帧
			cj188.POST("/simulate", controller.SimulateCj188)                  // 模拟协议数据
			cj188.DELETE("/simulate/:taskId", controller.StopSimulateCj188)    // 停止模拟任务
			cj188.GET("/events", controller.DeviceEventsSSE)                   // 设备事件SSE流
			cj188.GET("/status/:taskId", controller.GetDeviceStatus)           // 设备状态查询
			cj188.GET("/statistics/:taskId", controller.GetDeviceStatistics)   // 设备统计信息查询
			cj188.GET("/devices", controller.GetAllDevices)                    // 所有设备查询
		}

		// DLT645-2007 协议路由
		dlt645 := api.Group("/dlt645-2007")
		{
			dlt645.POST("/parse", controller.ParseDlt645_2007)                         // 解析协议帧
			dlt645.POST("/build", controller.BuildDlt645_2007)                         // 构建协议帧
			dlt645.POST("/simulate", controller.SimulateDlt645_2007)                   // 模拟协议数据
			dlt645.POST("/simulate/:taskId/stop", controller.StopSimulateDlt645_2007)  // 停止模拟任务
			dlt645.GET("/events", controller.DeviceEventsDlt645SSE)                    // 设备事件SSE流
			dlt645.GET("/status/:taskId", controller.GetDeviceStatusDLT645)            // 设备状态查询
			dlt645.GET("/statistics/:taskId", controller.GetDeviceStatisticsDLT645)    // 设备统计信息查询
		}
	}

	// SSE 路由 - 实时推送协议事件
	r.GET("/sse", handleSSE)
}

// handleSSE 处理SSE连接
func handleSSE(c *gin.Context) {
	// 设置SSE响应头
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("Access-Control-Allow-Origin", "*")

	// 获取SSE管理器
	manager := sse.GetDefaultManager()

	// 添加客户端（使用默认的userID和tenantID）
	userID := uint(1)
	tenantID := uint(1)
	client, err := manager.AddClient(userID, tenantID, c.Writer)
	if err != nil {
		logger.Errorf("SSE连接失败: %v", err)
		c.JSON(500, gin.H{"error": "SSE连接失败"})
		return
	}
	defer manager.RemoveClient(userID, tenantID)

	// 订阅协议事件
	bus := eventbus.GetDefaultBus()
	
	// 订阅CJ188协议事件
	unsubscribeCj188 := bus.Subscribe("protocol.cj188.*", func(ctx context.Context, event eventbus.Event) error {
		// 解析事件数据（可能是JSON字符串）
		var eventDataObj interface{}
		if dataStr, ok := event.Data().(string); ok {
			// 如果是字符串，尝试解析为JSON
			if err := json.Unmarshal([]byte(dataStr), &eventDataObj); err != nil {
				// 解析失败，直接使用字符串
				eventDataObj = dataStr
			}
		} else {
			eventDataObj = event.Data()
		}

		// 将事件数据发送给客户端
		eventData, _ := json.Marshal(map[string]interface{}{
			"topic":     event.Topic(),
			"data":      eventDataObj,
			"timestamp": event.Timestamp().Format("2006-01-02 15:04:05"),
		})
		return client.Send("protocol", string(eventData))
	})
	defer unsubscribeCj188()
	
	// 订阅DLT645-2007协议事件
	unsubscribeDlt645 := bus.Subscribe("protocol.dlt645-2007.*", func(ctx context.Context, event eventbus.Event) error {
		// 解析事件数据（可能是JSON字符串）
		var eventDataObj interface{}
		if dataStr, ok := event.Data().(string); ok {
			// 如果是字符串，尝试解析为JSON
			if err := json.Unmarshal([]byte(dataStr), &eventDataObj); err != nil {
				// 解析失败，直接使用字符串
				eventDataObj = dataStr
			}
		} else {
			eventDataObj = event.Data()
		}

		// 将事件数据发送给客户端
		eventData, _ := json.Marshal(map[string]interface{}{
			"topic":     event.Topic(),
			"data":      eventDataObj,
			"timestamp": event.Timestamp().Format("2006-01-02 15:04:05"),
		})
		return client.Send("protocol", string(eventData))
	})
	defer unsubscribeDlt645()

	// 发送初始连接消息
	client.Send("connect", `{"message":"已连接"}`)

	// 等待客户端断开连接
	<-client.Done
	logger.Info("SSE客户端已断开连接")
}
