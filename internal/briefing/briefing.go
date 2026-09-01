// 合并简报（账号状态 + 累计成本 + 当月出站流量）
// 对齐 Node 版 briefing.js
package briefing

import (
	"fmt"
	"time"

	"oci-panel/internal/ociutil"
	"oci-panel/internal/store"
)

func fmtTraffic(gb float64) string {
	if gb >= 1024 {
		return fmt.Sprintf("%.2fT", gb/1024)
	}
	return fmt.Sprintf("%.2fGB", gb)
}

// monthEgressGB 当月出站流量：实时查询；失败回退最近一次检测结果
func monthEgressGB(t *store.Tenant) *float64 {
	full := store.GetTenantWithKey(t.ID)
	if full == nil || full.PrivateKeyEnc == "" {
		return t.TrafficLastTotalGB
	}
	c, err := ociutil.CredsFromTenant(full)
	if err != nil {
		return t.TrafficLastTotalGB
	}
	tr, err := ociutil.QueryTenantMonthTraffic(c)
	if err != nil {
		return t.TrafficLastTotalGB
	}
	store.UpdateTenantFields(t.ID, store.TenantFields{
		TrafficLastChecked: strPtr(time.Now().UTC().Format(time.RFC3339)),
		TrafficLastTotalGB: &tr.EgressGB,
	})
	return &tr.EgressGB
}

func strPtr(s string) *string { return &s }

// BuildBriefing 生成合并 OCI 简报
func BuildBriefing() (title, content string) {
	now := time.Now()
	today := now.UTC().Format("2006-01-02")

	// 累计成本：费用数据自开户日回溯落库，汇总即账号生命周期总花费
	r := store.GetDailyCosts("2000-01-01", today)
	costByTenant := map[int]float64{}
	for _, d := range r.Days {
		for _, tt := range d.Tenants {
			costByTenant[tt.ID] += tt.Total
		}
	}
	totalCost := r.Summary.Total

	tenants := store.ListTenants()
	abnormal := 0
	for _, t := range tenants {
		if !(t.SyncStatus == "ok" && (t.AccountState == "" || t.AccountState == "ACTIVE")) {
			abnormal++
		}
	}
	healthText := "账号正常"
	if abnormal != 0 {
		healthText = fmt.Sprintf("账号异常(%d/%d)", abnormal, len(tenants))
	}

	blocks := make([]string, 0, len(tenants))
	for i, t := range tenants {
		name := t.CustomName
		if name == "" {
			name = t.Name
		}
		region := t.HomeRegion
		if region == "" {
			region = t.Region
		}
		if region == "" {
			region = "-"
		}
		cost := fmt.Sprintf("$%.2f", costByTenant[t.ID])
		egressStr := "-"
		if e := monthEgressGB(&t); e != nil {
			egressStr = fmtTraffic(*e)
		}
		// 存活天数 = 今天 - 开户日
		aliveDays := "-"
		if t.AccountCreatedAt != "" {
			if created, err := time.Parse(time.RFC3339, t.AccountCreatedAt); err == nil {
				if d := int(now.Sub(created).Hours() / 24); d >= 0 {
					aliveDays = fmt.Sprintf("%d天", d)
				}
			} else {
				if created, err := time.Parse("2006-01-02T15:04:05.000Z", t.AccountCreatedAt); err == nil {
					if d := int(now.Sub(created).Hours() / 24); d >= 0 {
						aliveDays = fmt.Sprintf("%d天", d)
					}
				}
			}
		}
		// 实例明细：名称 + 规格 + 开机天数（含非运行态）
		lines := []string{}
		for _, inst := range store.ListInstances(t.ID) {
			uptimeDays := "-"
			if inst.LifecycleState == "RUNNING" && inst.RunningSince != nil {
				if rs, err := time.Parse(time.RFC3339, *inst.RunningSince); err == nil {
					if d := int(now.Sub(rs).Hours() / 24); d >= 0 {
						uptimeDays = fmt.Sprintf("%d", d)
					}
				}
			}
			cpu, mem := "-", "-"
			if inst.OcpuCount != nil {
				cpu = trimF(*inst.OcpuCount) + "C"
			}
			if inst.MemoryInGBs != nil {
				mem = trimF(*inst.MemoryInGBs) + "G"
			}
			lines = append(lines, fmt.Sprintf("-%s：%s / %s  开机天数：%s", inst.DisplayName, cpu, mem, uptimeDays))
		}
		block := fmt.Sprintf("【租户%d】%s\n区域：%s ｜ 存活：%s\n成本：%s\n当月出站流量：%s",
			i+1, name, region, aliveDays, cost, egressStr)
		if len(lines) > 0 {
			block += "\n" + joinLines(lines)
		}
		blocks = append(blocks, block)
	}
	if len(blocks) == 0 {
		content = "暂无租户"
	} else {
		content = joinPara(blocks)
	}
	title = fmt.Sprintf("OCI简报：%s 累计花费$%.2f", healthText, totalCost)
	return title, content
}

func trimF(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%g", f)
}

func joinLines(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "\n"
		}
		out += l
	}
	return out
}

func joinPara(blocks []string) string {
	out := ""
	for i, b := range blocks {
		if i > 0 {
			out += "\n\n"
		}
		out += b
	}
	return out
}
