// 费用查询 — 基于 UsageapiClient.RequestSummarizedUsages
// 对齐 Node 版 oci-cost.js：按日聚合 + 按 SKU 明细
package ociutil

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/usageapi"

	"oci-panel/internal/store"
)

func newUsageapiClient(c Creds) (usageapi.UsageapiClient, error) {
	// Usage API 用 Home Region（对齐 Node 版 makeProvider：home_region || region）
	region := c.HomeRegion
	if region == "" {
		region = c.Region
	}
	pc := c.WithRegion(region)
	p, err := makeProvider(pc)
	if err != nil {
		return usageapi.UsageapiClient{}, err
	}
	cl, err := usageapi.NewUsageapiClientWithConfigurationProvider(p)
	if err != nil {
		return usageapi.UsageapiClient{}, err
	}
	cl.SetRegion(region)
	return cl, nil
}

// ---- 分类映射：service → 计算/存储/网络/其他（对齐 Node 版 categorize） ----

func Categorize(service string) string {
	if service == "" {
		return "其他"
	}
	s := strings.ToLower(service)
	if strings.Contains(s, "compute") {
		return "计算"
	}
	if strings.Contains(s, "block") || strings.Contains(s, "storage") || strings.Contains(s, "object") || strings.Contains(s, "file") {
		return "存储"
	}
	if strings.Contains(s, "network") || strings.Contains(s, "vcn") || strings.Contains(s, "load") || strings.Contains(s, "dns") {
		return "网络"
	}
	if strings.Contains(s, "database") || strings.Contains(s, "autonomous") {
		return "数据库"
	}
	return "其他"
}

// queryUsages 通用 Usage 查询（分页 + 重试 3 次）
func queryUsages(ctx context.Context, c Creds, startUtc, endUtc time.Time, granularity usageapi.RequestSummarizedUsagesDetailsGranularityEnum, groupBy []string) ([]usageapi.UsageSummary, error) {
	cl, err := newUsageapiClient(c)
	if err != nil {
		return nil, err
	}
	var all []usageapi.UsageSummary
	var pageToken *string
	attempts := 0
	const maxAttempts = 3
	for {
		resp, err := cl.RequestSummarizedUsages(ctx, usageapi.RequestSummarizedUsagesRequest{
			RequestSummarizedUsagesDetails: usageapi.RequestSummarizedUsagesDetails{
				TenantId:         &c.TenancyOcid,
				TimeUsageStarted: &common.SDKTime{Time: startUtc},
				TimeUsageEnded:   &common.SDKTime{Time: endUtc},
				Granularity:      granularity,
				GroupBy:          groupBy,
			},
			Page:  pageToken,
			Limit: common.Int(500),
		})
		if err != nil {
			attempts++
			if attempts >= maxAttempts {
				return nil, err
			}
			sleep(1000 * attempts)
			continue
		}
		attempts = 0
		if resp.UsageAggregation.Items != nil {
			all = append(all, resp.UsageAggregation.Items...)
		}
		if resp.OpcNextPage == nil || *resp.OpcNextPage == "" {
			break
		}
		pageToken = resp.OpcNextPage
	}
	return all, nil
}

// ---- 按日聚合 ----

// DailyCostItem 单日费用
type DailyCostItem struct {
	Date    string  `json:"date"`
	Total   float64 `json:"total"`
	Compute float64 `json:"compute"`
	Storage float64 `json:"storage"`
	Network float64 `json:"network"`
	Other   float64 `json:"other"`
}

// CostSummaryView 汇总
type CostSummaryView struct {
	Total   float64 `json:"total"`
	Compute float64 `json:"compute"`
	Storage float64 `json:"storage"`
	Network float64 `json:"network"`
	Other   float64 `json:"other"`
}

// DailyCostResult 查询结果（对齐 Node 版 queryDailyCost 返回结构）
type DailyCostResult struct {
	Days              []string       `json:"days"`
	Currency          string         `json:"currency"`
	StartDateEffective string        `json:"startDateEffective"`
	Clamped           bool           `json:"clamped"`
	AccountCreatedAt  string         `json:"accountCreatedAt,omitempty"`
	Daily             []DailyCostItem `json:"daily"`
	Summary           CostSummaryView `json:"summary"`
}

// QueryDailyCost 按日 + 按类别聚合（起始日截断到开户日）
func QueryDailyCost(c Creds, startDateStr, endDateStr string) (*DailyCostResult, error) {
	ctx := context.Background()
	startUtc, err := time.Parse("2006-01-02", startDateStr)
	if err != nil {
		return nil, fmt.Errorf("起始日期格式错误: %w", err)
	}
	endDate, err := time.Parse("2006-01-02", endDateStr)
	if err != nil {
		return nil, fmt.Errorf("结束日期格式错误: %w", err)
	}
	// 结束日期 +1 天（OCI 区间左闭右开）
	endUtc := endDate.AddDate(0, 0, 1)

	// 开户前没有账单数据：截断到开户日（UTC 当天）
	clamped := false
	startDateEffective := startDateStr
	if c.AccountCreatedAt != "" {
		created, err := parseAnyTime(c.AccountCreatedAt)
		if err == nil && startUtc.Before(created) {
			createdDay := time.Date(created.Year(), created.Month(), created.Day(), 0, 0, 0, 0, time.UTC)
			startUtc = createdDay
			startDateEffective = createdDay.Format("2006-01-02")
			clamped = true
		}
	}

	items, err := queryUsages(ctx, c, startUtc, endUtc, usageapi.RequestSummarizedUsagesDetailsGranularityDaily, []string{"service"})
	if err != nil {
		return nil, err
	}

	// 补全每一天
	var dayList []string
	cursor := startUtc
	for cursor.Before(endUtc) {
		dayList = append(dayList, cursor.Format("2006-01-02"))
		cursor = cursor.AddDate(0, 0, 1)
	}
	daily := map[string]*DailyCostItem{}
	for _, d := range dayList {
		daily[d] = &DailyCostItem{Date: d}
	}

	currency := "USD"
	var summary CostSummaryView
	for _, item := range items {
		date := ""
		if item.TimeUsageStarted != nil {
			date = item.TimeUsageStarted.Format("2006-01-02")
		}
		if date == "" {
			continue
		}
		d, ok := daily[date]
		if !ok {
			continue
		}
		var amount float64
		if item.ComputedAmount != nil {
			amount = float64(*item.ComputedAmount)
		}
		if item.Currency != nil && *item.Currency != "" {
			currency = *item.Currency
		}
		switch Categorize(str(item.Service)) {
		case "计算":
			d.Compute += amount
			summary.Compute += amount
		case "存储":
			d.Storage += amount
			summary.Storage += amount
		case "网络":
			d.Network += amount
			summary.Network += amount
		default:
			d.Other += amount
			summary.Other += amount
		}
		d.Total += amount
		summary.Total += amount
	}

	list := make([]DailyCostItem, 0, len(dayList))
	for _, d := range dayList {
		v := daily[d]
		v.Total = round4(v.Total)
		v.Compute = round4(v.Compute)
		v.Storage = round4(v.Storage)
		v.Network = round4(v.Network)
		v.Other = round4(v.Other)
		list = append(list, *v)
	}
	summary.Total = round4(summary.Total)
	summary.Compute = round4(summary.Compute)
	summary.Storage = round4(summary.Storage)
	summary.Network = round4(summary.Network)
	summary.Other = round4(summary.Other)

	return &DailyCostResult{
		Days:               dayList,
		Currency:           currency,
		StartDateEffective: startDateEffective,
		Clamped:            clamped,
		AccountCreatedAt:   c.AccountCreatedAt,
		Daily:              list,
		Summary:            summary,
	}, nil
}

// ---- 明细查询 ----

// CostDetailItem 费用明细行
type CostDetailItem struct {
	Date           string  `json:"date"`
	Service        string  `json:"service"`
	Category       string  `json:"category"`
	SkuName        string  `json:"skuName"`
	ResourceID     string  `json:"resourceId"`
	ResourceName   string  `json:"resourceName"`
	ComputedAmount float64 `json:"computedAmount"`
	Currency       string  `json:"currency"`
}

// QueryCostDetails 指定日期范围内的费用明细（按 resourceId + skuName 分组）
func QueryCostDetails(c Creds, startDateStr, endDateStr string) ([]CostDetailItem, error) {
	ctx := context.Background()
	startUtc, err := time.Parse("2006-01-02", startDateStr)
	if err != nil {
		return nil, fmt.Errorf("起始日期格式错误: %w", err)
	}
	endDate, err := time.Parse("2006-01-02", endDateStr)
	if err != nil {
		return nil, fmt.Errorf("结束日期格式错误: %w", err)
	}
	endUtc := endDate.AddDate(0, 0, 1)

	items, err := queryUsages(ctx, c, startUtc, endUtc, usageapi.RequestSummarizedUsagesDetailsGranularityDaily, []string{"resourceId", "skuName", "service"})
	if err != nil {
		return nil, err
	}
	out := make([]CostDetailItem, 0, len(items))
	for _, i := range items {
		date := ""
		if i.TimeUsageStarted != nil {
			date = i.TimeUsageStarted.Format("2006-01-02")
		}
		var amount float64
		if i.ComputedAmount != nil {
			amount = float64(*i.ComputedAmount)
		}
		cur := "USD"
		if i.Currency != nil && *i.Currency != "" {
			cur = *i.Currency
		}
		sku := str(i.SkuName)
		if sku == "" {
			sku = "-"
		}
		rid := str(i.ResourceId)
		if rid == "" {
			rid = "-"
		}
		rname := str(i.ResourceName)
		if rname == "" {
			rname = "-"
		}
		out = append(out, CostDetailItem{
			Date:           date,
			Service:        str(i.Service),
			Category:       Categorize(str(i.Service)),
			SkuName:        sku,
			ResourceID:     rid,
			ResourceName:   rname,
			ComputedAmount: round4(amount),
			Currency:       cur,
		})
	}
	return out, nil
}

// ---- 每日费用同步（落库） ----

const (
	syncRecentDays   = 3   // 日常同步：补最近 N 天（OCI 账单有 ~24h 延迟）
	backfillMaxDays  = 180 // 首次同步：最多回溯 180 天
)

// TenantCostSyncResult 单租户同步结果
type TenantCostSyncResult struct {
	ID    int     `json:"id"`
	Name  string  `json:"name"`
	Days  int     `json:"days"`
	Error string  `json:"error,omitempty"`
}

// SyncTenantCosts 同步单个租户费用到 store
// 首次（库中无数据）：从开户日（最多回溯 180 天）补齐到今天；日常：只重查最近 3 天
func SyncTenantCosts(tenantID int) TenantCostSyncResult {
	t := store.GetTenantWithKey(tenantID)
	if t == nil {
		return TenantCostSyncResult{ID: tenantID, Days: 0, Error: "租户不存在"}
	}
	c, err := CredsFromTenant(t)
	if err != nil {
		return TenantCostSyncResult{ID: tenantID, Days: 0, Error: err.Error()}
	}
	c.AccountCreatedAt = t.AccountCreatedAt

	today := time.Now().UTC()
	todayStr := today.Format("2006-01-02")

	var startDate string
	if store.HasCostData(tenantID) {
		startDate = today.AddDate(0, 0, -(syncRecentDays - 1)).Format("2006-01-02")
	} else {
		startDate = today.AddDate(0, 0, -(backfillMaxDays - 1)).Format("2006-01-02")
		if t.AccountCreatedAt != "" {
			if created, err := parseAnyTime(t.AccountCreatedAt); err == nil {
				createdStr := created.Format("2006-01-02")
				if createdStr > startDate {
					startDate = createdStr
				}
			}
		}
	}
	if startDate > todayStr {
		startDate = todayStr
	}

	r, err := QueryDailyCost(c, startDate, todayStr)
	if err != nil {
		return TenantCostSyncResult{ID: tenantID, Days: 0, Error: ErrInfo(err)}
	}
	inputs := make([]store.SaveDailyCostInput, 0, len(r.Daily))
	for _, d := range r.Daily {
		inputs = append(inputs, store.SaveDailyCostInput{
			Date:     d.Date,
			Compute:  d.Compute,
			Storage:  d.Storage,
			Network:  d.Network,
			Other:    d.Other,
			Total:    d.Total,
			Currency: r.Currency,
		})
	}
	store.SaveDailyCosts(tenantID, inputs)
	return TenantCostSyncResult{ID: tenantID, Days: len(r.Daily)}
}

// SyncAllTenantsCosts 同步所有租户（cron 每天 8 点 + 页面手动触发）
func SyncAllTenantsCosts() []TenantCostSyncResult {
	tenants := store.ListTenants()
	results := make([]TenantCostSyncResult, 0, len(tenants))
	for _, t := range tenants {
		r := SyncTenantCosts(t.ID)
		name := t.CustomName
		if name == "" {
			name = t.Name
		}
		r.Name = name
		results = append(results, r)
	}
	return results
}

// round4 保留 4 位小数（对齐 Node 版）
func round4(n float64) float64 {
	return math.Round(n*10000) / 10000
}

// parseAnyTime 兼容多种时间格式
func parseAnyTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	// 去掉毫秒位再试（Store 里的格式 2006/1/2 15:04:05 等）
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05.000Z", "2006-01-02T15:04:05.000Z07:00", "2006/1/2 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("无法解析时间: %s", s)
}
