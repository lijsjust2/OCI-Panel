// 流量查询 — 基于 Monitoring API 的 VnicToNetworkBytes/VnicFromNetworkBytes 指标
// 对齐 Node 版 oci-traffic.js
package ociutil

import (
	"context"
	"fmt"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/monitoring"

	"oci-panel/internal/store"
)

func newMonitoringClient(c Creds) (monitoring.MonitoringClient, error) {
	// Monitoring 用 Home Region（对齐 Node 版 makeProvider：home_region || region）
	region := c.HomeRegion
	if region == "" {
		region = c.Region
	}
	pc := c.WithRegion(region)
	p, err := makeProvider(pc)
	if err != nil {
		return monitoring.MonitoringClient{}, err
	}
	cl, err := monitoring.NewMonitoringClientWithConfigurationProvider(p)
	if err != nil {
		return monitoring.MonitoringClient{}, err
	}
	cl.SetRegion(region)
	return cl, nil
}

// homeComputeClient Home Region 的 Compute 客户端（VNIC Attachment 查询用）
func homeComputeClient(c Creds) (core.ComputeClient, error) {
	region := c.HomeRegion
	if region == "" {
		region = c.Region
	}
	return NewComputeClient(c.WithRegion(region))
}

// listAllVnicAttachments 列出租户所有 VNIC Attachments（跨所有 AD 与 Compartment）
// ListVnicAttachments 不支持 subtree 参数，需逐 Compartment 查询
func listAllVnicAttachments(c Creds) ([]core.VnicAttachment, error) {
	ctx := context.Background()
	cmp, err := homeComputeClient(c)
	if err != nil {
		return nil, err
	}
	compartments := []string{c.TenancyOcid}
	if subs, err := ListCompartments(c); err == nil {
		for _, s := range subs {
			compartments = append(compartments, s.ID)
		}
	}
	var result []core.VnicAttachment
	for _, compartmentId := range compartments {
		req := core.ListVnicAttachmentsRequest{
			CompartmentId: &compartmentId,
			Limit:         common.Int(100),
		}
		for {
			resp, err := cmp.ListVnicAttachments(ctx, req)
			if err != nil {
				return nil, err
			}
			result = append(result, resp.Items...)
			if resp.OpcNextPage == nil || *resp.OpcNextPage == "" {
				break
			}
			req.Page = resp.OpcNextPage
		}
	}
	return result, nil
}

// queryVnicTraffic 单个 VNIC 在时间区间内的流量总量（字节）
// direction: "egress" / "ingress"
func queryVnicTraffic(ctx context.Context, c Creds, vnicId, direction string, startTime, endTime time.Time) (float64, error) {
	monitor, err := newMonitoringClient(c)
	if err != nil {
		return 0, err
	}
	// 月度查询用 1h 粒度（1m 只支持 ~30 天）
	metric := "VnicFromNetworkBytes"
	if direction == "egress" {
		metric = "VnicToNetworkBytes"
	}
	query := fmt.Sprintf(`%s[1h]{resourceId = "%s"}.sum()`, metric, vnicId)
	resp, err := monitor.SummarizeMetricsData(ctx, monitoring.SummarizeMetricsDataRequest{
		CompartmentId: &c.TenancyOcid,
		SummarizeMetricsDataDetails: monitoring.SummarizeMetricsDataDetails{
			Namespace: common.String("oci_vcn"),
			Query:     &query,
			StartTime: &common.SDKTime{Time: startTime},
			EndTime:   &common.SDKTime{Time: endTime},
		},
	})
	if err != nil {
		return 0, err
	}
	var total float64
	for _, item := range resp.Items {
		for _, dp := range item.AggregatedDatapoints {
			if dp.Value != nil {
				total += *dp.Value
			}
		}
	}
	return total, nil
}

// ---- 月度流量汇总 ----

// VnicTrafficDetail 单 VNIC 流量明细
type VnicTrafficDetail struct {
	VnicID     string  `json:"vnicId"`
	InstanceID string  `json:"instanceId"`
	EgressGB   float64 `json:"egressGB"`
	IngressGB  float64 `json:"ingressGB"`
	Error      string  `json:"error,omitempty"`
}

// TenantTrafficResult 租户本月流量
type TenantTrafficResult struct {
	EgressBytes  float64             `json:"egressBytes"`
	IngressBytes float64             `json:"ingressBytes"`
	EgressGB     float64             `json:"egressGB"`
	IngressGB    float64             `json:"ingressGB"`
	Details      []VnicTrafficDetail `json:"details"`
	MonthStart   string              `json:"monthStart"`
	QueryTime    string              `json:"queryTime"`
	Error        string              `json:"error,omitempty"`
}

// QueryTenantMonthTraffic 查询租户本月所有 VNIC 的出站/入站总量
func QueryTenantMonthTraffic(c Creds) (*TenantTrafficResult, error) {
	ctx := context.Background()
	now := time.Now().UTC()
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	atts, err := listAllVnicAttachments(c)
	if err != nil {
		return nil, err
	}
	var egressBytes, ingressBytes float64
	details := make([]VnicTrafficDetail, 0, len(atts))
	for _, att := range atts {
		if att.VnicId == nil || *att.VnicId == "" {
			continue
		}
		vnicId := *att.VnicId
		d := VnicTrafficDetail{VnicID: vnicId, InstanceID: str(att.InstanceId)}
		eG, eErr := queryVnicTraffic(ctx, c, vnicId, "egress", monthStart, now)
		iG, iErr := queryVnicTraffic(ctx, c, vnicId, "ingress", monthStart, now)
		if eErr != nil || iErr != nil {
			// 单个 VNIC 失败不阻断
			if eErr != nil {
				d.Error = ErrInfo(eErr)
			} else {
				d.Error = ErrInfo(iErr)
			}
		} else {
			egressBytes += eG
			ingressBytes += iG
			d.EgressGB = round4(eG / 1024 / 1024 / 1024)
			d.IngressGB = round4(iG / 1024 / 1024 / 1024)
		}
		details = append(details, d)
	}
	return &TenantTrafficResult{
		EgressBytes:  egressBytes,
		IngressBytes: ingressBytes,
		EgressGB:     round4(egressBytes / 1024 / 1024 / 1024),
		IngressGB:    round4(ingressBytes / 1024 / 1024 / 1024),
		Details:      details,
		MonthStart:   monthStart.Format("2006-01-02"),
		QueryTime:    now.Format(time.RFC3339),
	}, nil
}

// ---- 预警检查 ----

// TrafficCheckResult 一次完整预警检查的结果
type TrafficCheckResult struct {
	Ok               bool               `json:"ok"`
	EgressGB         float64            `json:"egressGB"`
	IngressGB        float64            `json:"ingressGB"`
	Threshold        float64            `json:"threshold"`
	Exceeded         bool               `json:"exceeded"`
	ShutdownPerformed bool              `json:"shutdownPerformed"`
	ShutdownError    string             `json:"shutdownError,omitempty"`
	Details          []VnicTrafficDetail `json:"details"`
	MonthStart       string             `json:"monthStart"`
	Error            string             `json:"error,omitempty"`
}

// CheckAndAlert 执行一次完整的预警检查：查询流量 → 判断超阈值 → 自动关机
// t 为含流量配置的租户；instances 为该租户的本地实例列表（用于关机）
func CheckAndAlert(t *store.Tenant) *TrafficCheckResult {
	c, err := CredsFromTenant(t)
	if err != nil {
		return &TrafficCheckResult{Error: err.Error()}
	}
	traffic, err := QueryTenantMonthTraffic(c)
	if err != nil {
		return &TrafficCheckResult{Error: ErrInfo(err)}
	}
	thresholdGB := t.TrafficThreshold
	if thresholdGB == 0 {
		thresholdGB = 9000
	}
	exceeded := traffic.EgressGB > thresholdGB
	result := &TrafficCheckResult{
		Ok:         true,
		EgressGB:   traffic.EgressGB,
		IngressGB:  traffic.IngressGB,
		Threshold:  thresholdGB,
		Exceeded:   exceeded,
		Details:    traffic.Details,
		MonthStart: traffic.MonthStart,
	}
	if exceeded && t.TrafficAutoshutdown {
		// 停止所有 RUNNING 状态的实例
		for _, inst := range store.ListInstances(t.ID) {
			if inst.LifecycleState == "RUNNING" {
				r := instanceAction(c, inst.OciID, "SOFTSTOP")
				if r.Ok {
					result.ShutdownPerformed = true
				} else {
					result.ShutdownError = r.Error
				}
			}
		}
	}
	return result
}
