// Package scheduler 定时任务（对齐 Node 版 server.js 中的三个 cron）
// 1. 流量预警检查：每 30 分钟
// 2. 费用同步：每天 8:00
// 3. 用户通知：每分钟扫描，按各用户 notify_time 定点推送
package scheduler

import (
	"fmt"
	"log"
	"time"

	"github.com/robfig/cron/v3"

	"oci-panel/internal/briefing"
	"oci-panel/internal/ociutil"
	"oci-panel/internal/push"
	"oci-panel/internal/store"
)

var trafficAlertDedupe = map[string]bool{} // key = tenantId:YYYY-MM-DD，同一租户同一天只推一次告警
var notifyRunDedupe = map[string]bool{}    // key = username:YYYY-MM-DD

// Start 启动全部定时任务，返回 cron 实例（可用于测试触发）
func Start() *cron.Cron {
	c := cron.New()

	// 定时流量预警检查：每 30 分钟
	c.AddFunc("*/30 * * * *", trafficCheckJob)
	log.Println("定时流量预警已启动（每30分钟检查一次，通知按用户渠道推送）")

	// 定时费用同步：每天 8:00
	c.AddFunc("0 8 * * *", costSyncJob)
	log.Println("定时费用同步已启动（每天 8:00 同步一次）")

	// 用户通知：每分钟扫描
	c.AddFunc("* * * * *", userNotifyJob)
	log.Println("通知任务调度已启动（按每个用户的 notify_time 定点执行）")

	c.Start()
	return c
}

// trafficCheckJob 每 30 分钟：检查启用流量预警的租户，超阈值推送告警
func trafficCheckJob() {
	for _, t := range store.ListTenants() {
		if !t.TrafficEnabled {
			continue
		}
		full := store.GetTenantWithKey(t.ID)
		if full == nil {
			continue
		}
		result := ociutil.CheckAndAlert(full)
		now := time.Now().UTC().Format(time.RFC3339)
		store.UpdateTenantFields(t.ID, store.TenantFields{
			TrafficLastChecked: &now,
			TrafficLastTotalGB: &result.EgressGB,
			TrafficLastExceeded: &result.Exceeded,
		})
		if result.Error != "" {
			log.Printf("[流量检查] 租户 %s 失败: %s", t.Name, result.Error)
			continue
		}
		if result.Exceeded {
			key := fmt.Sprintf("%d:%s", t.ID, time.Now().UTC().Format("2006-01-02"))
			already := trafficAlertDedupe[key]
			log.Printf("[流量预警] 租户 %s 本月出站 %.2f GB > 阈值 %.0f GB%s%s",
				t.Name, result.EgressGB, result.Threshold,
				shutdownSuffix(result.ShutdownPerformed, result.ShutdownError),
				dedupeSuffix(already))
			if already {
				continue
			}
			trafficAlertDedupe[key] = true
			pushTrafficAlert(t, result)
		} else {
			log.Printf("[流量检查] 租户 %s 本月出站 %.2f GB / 阈值 %.0f GB", t.Name, result.EgressGB, result.Threshold)
		}
	}
}

func shutdownSuffix(performed bool, errStr string) string {
	if !performed {
		return ""
	}
	if errStr != "" {
		return "（自动关机失败：" + errStr + "）"
	}
	return "，已自动关机"
}

func dedupeSuffix(already bool) string {
	if already {
		return "（今日已推送过）"
	}
	return ""
}

// pushTrafficAlert 给所有勾选流量预警通知的用户推送（走各自选择的 notify_channel）
func pushTrafficAlert(t store.Tenant, result *ociutil.TrafficCheckResult) {
	name := t.CustomName
	if name == "" {
		name = t.Name
	}
	title := fmt.Sprintf("⚠️ 流量预警：%s", name)
	content := fmt.Sprintf("本月出站流量：%.2f GB\n阈值：%.0f GB\n占用：%.1f%%\n%s",
		result.EgressGB, result.Threshold, result.EgressGB/result.Threshold*100,
		shutdownLine(result.ShutdownPerformed))
	for _, u := range store.ListUsers() {
		s := store.GetUserSettings(u.Username)
		if !s.NotifyTrafficAlert {
			continue
		}
		ch := s.NotifyChannel
		if ch == "" {
			ch = "bark"
		}
		r := push.SendAlertText(s, ch, title, content)
		if !r.Ok {
			log.Printf("[流量告警推送失败] %s: %s", u.Username, r.Error)
		}
	}
}

func shutdownLine(performed bool) string {
	if performed {
		return "✗ 已自动执行软关机"
	}
	return "尚未关机"
}

// costSyncJob 每天 8:00：同步各租户按日费用
func costSyncJob() {
	log.Println("[费用同步] 开始每日同步...")
	results := ociutil.SyncAllTenantsCosts()
	for _, r := range results {
		if r.Error != "" {
			log.Printf("[费用同步] 租户 %s 失败: %s", r.Name, r.Error)
		} else {
			log.Printf("[费用同步] 租户 %s 已更新 %d 天数据", r.Name, r.Days)
		}
	}
}

// userNotifyJob 每分钟：谁到点了就执行谁的通知
func userNotifyJob() {
	now := time.Now()
	tNow := now.Format("15:04")
	dStr := now.UTC().Format("2006-01-02")
	for _, u := range store.ListUsers() {
		s := store.GetUserSettings(u.Username)
		if !s.NotifyEnabled || s.NotifyTime != tNow {
			continue
		}
		key := u.Username + ":" + dStr
		if notifyRunDedupe[key] {
			continue
		}
		notifyRunDedupe[key] = true
		go runUserNotify(u.Username) // 并发执行，避免用户之间串行阻塞
	}
}

func runUserNotify(username string) {
	s := store.GetUserSettings(username)
	if !s.NotifyEnabled {
		return
	}
	// 两项任务共用一个模板：勾选任一项，即推送一条合并的 OCI 简报
	if !s.NotifyCostsDaily && !s.NotifyAccountHealth {
		return
	}
	title, content := briefing.BuildBriefing()
	ch := s.NotifyChannel
	if ch == "" {
		ch = "bark"
	}
	r := push.SendAlertText(s, ch, title, content)
	if !r.Ok {
		log.Printf("[通知任务] %s 推送失败 (%s): %s", username, title, r.Error)
	} else {
		log.Printf("[通知任务] %s 已推送 %s", username, title)
	}
}
