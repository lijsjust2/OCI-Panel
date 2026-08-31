package ociutil

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"

	"oci-panel/internal/store"
)

func sleep(ms int) {
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

// InstanceListItem OCI 实例（含同步补充的网络/引导卷信息）
type InstanceListItem struct {
	ID                string
	DisplayName       string
	LifecycleState    string
	Shape             string
	AvailabilityDomain string
	CompartmentID     string
	TimeCreated       string
	PrivateIP         string
	PublicIP          string
	IPv6              string
	BootVolumeID      string
	BootVolumeSize    *float64
	VpusPerGB         *float64
	Ocpus             *float64
	MemoryInGBs       *float64
}

func toRaw(region string, i core.Instance, vnic *core.Vnic, bv *core.BootVolume) store.RawInstance {
	raw := store.RawInstance{
		ID:                str(i.Id),
		DisplayName:       str(i.DisplayName),
		LifecycleState:    string(i.LifecycleState),
		Shape:             str(i.Shape),
		AvailabilityDomain: str(i.AvailabilityDomain),
		CompartmentID:     str(i.CompartmentId),
		Region:            region,
	}
	if i.TimeCreated != nil {
		raw.TimeCreated = i.TimeCreated.Format(timeFormatRFC3339Milli)
	}
	if vnic != nil {
		if vnic.PrivateIp != nil {
			raw.PrivateIPs = []string{*vnic.PrivateIp}
		}
		if vnic.PublicIp != nil {
			raw.PublicIPs = []string{*vnic.PublicIp}
		}
		raw.IPv6s = append(raw.IPv6s, vnic.Ipv6Addresses...)
	}
	if i.ShapeConfig != nil {
		if i.ShapeConfig.Ocpus != nil {
			f := float64(*i.ShapeConfig.Ocpus)
			raw.Ocpus = &f
		}
		if i.ShapeConfig.MemoryInGBs != nil {
			f := float64(*i.ShapeConfig.MemoryInGBs)
			raw.MemoryInGBs = &f
		}
	}
	// 架构判断（对齐 Node 版）
	shape, desc := raw.Shape, ""
	if i.ShapeConfig != nil && i.ShapeConfig.ProcessorDescription != nil {
		desc = *i.ShapeConfig.ProcessorDescription
	}
	if strings.Contains(shape, "A1") || strings.Contains(strings.ToLower(desc), "ampere") {
		raw.Arch = "ARM"
	} else if desc != "" || shape != "" {
		raw.Arch = "x86"
	}
	if bv != nil {
		raw.BootVolumeID = str(bv.Id)
		if bv.SizeInGBs != nil {
			f := float64(*bv.SizeInGBs)
			raw.BootVolumeSize = &f
		}
		if bv.VpusPerGB != nil {
			f := float64(*bv.VpusPerGB)
			raw.VpusPerGB = &f
		}
	}
	return raw
}

// ---- 分页列举 ----

func listInstancesInCompartment(c Creds, compartmentId string) ([]core.Instance, error) {
	ctx := context.Background()
	cmp, err := NewComputeClient(c)
	if err != nil {
		return nil, err
	}
	var result []core.Instance
	req := core.ListInstancesRequest{CompartmentId: &compartmentId, Limit: common.Int(100)}
	for {
		resp, err := cmp.ListInstances(ctx, req)
		if err != nil {
			return nil, err
		}
		result = append(result, resp.Items...)
		if resp.OpcNextPage == nil || *resp.OpcNextPage == "" {
			break
		}
		req.Page = resp.OpcNextPage
	}
	return result, nil
}

// GetPrimaryVnic 主 VNIC（公网/私网/IPv6）
func GetPrimaryVnic(c Creds, instanceId, compartmentId string) (*core.Vnic, error) {
	ctx := context.Background()
	cmp, err := NewComputeClient(c)
	if err != nil {
		return nil, err
	}
	net, err := NewNetworkClient(c)
	if err != nil {
		return nil, err
	}
	var attachments []core.VnicAttachment
	req := core.ListVnicAttachmentsRequest{InstanceId: &instanceId, CompartmentId: &compartmentId}
	for {
		resp, err := cmp.ListVnicAttachments(ctx, req)
		if err != nil {
			return nil, err
		}
		attachments = append(attachments, resp.Items...)
		if resp.OpcNextPage == nil || *resp.OpcNextPage == "" {
			break
		}
		req.Page = resp.OpcNextPage
	}
	// 优先返回主 VNIC，否则第一个
	pick := func(primary bool) *core.Vnic {
		for _, att := range attachments {
			if att.VnicId == nil {
				continue
			}
			resp, err := net.GetVnic(ctx, core.GetVnicRequest{VnicId: att.VnicId})
			if err != nil {
				continue
			}
			isPrimary := resp.Vnic.IsPrimary != nil && *resp.Vnic.IsPrimary
			if isPrimary == primary {
				v := resp.Vnic
				return &v
			}
		}
		return nil
	}
	if v := pick(true); v != nil {
		return v, nil
	}
	return pick(false), nil
}

// GetBootVolume 引导卷（磁盘大小 + VPU）
func GetBootVolume(c Creds, instanceId, compartmentId string) (*core.BootVolume, error) {
	ctx := context.Background()
	cmp, err := NewComputeClient(c)
	if err != nil {
		return nil, err
	}
	bs, err := NewBlockstorageClient(c)
	if err != nil {
		return nil, err
	}
	resp, err := cmp.ListBootVolumeAttachments(ctx, core.ListBootVolumeAttachmentsRequest{
		InstanceId: &instanceId, CompartmentId: &compartmentId,
	})
	if err != nil {
		return nil, err
	}
	for _, att := range resp.Items {
		if att.BootVolumeId == nil {
			continue
		}
		bv, err := bs.GetBootVolume(ctx, core.GetBootVolumeRequest{BootVolumeId: att.BootVolumeId})
		if err != nil {
			continue
		}
		v := bv.BootVolume
		return &v, nil
	}
	return nil, nil
}

// SyncResult 全量同步结果
type SyncResult struct {
	Raws        []store.RawInstance
	Errors      []string
	HomeRegion  string
	RegionCount int
}

// ListAllInstances 同步租户所有实例（遍历区域 × Compartment，取主 VNIC 与引导卷）
func ListAllInstances(c Creds) (*SyncResult, error) {
	regions, err := ListSubscribedRegions(c)
	if err != nil {
		return nil, err
	}
	result := &SyncResult{Raws: []store.RawInstance{}}
	for _, r := range regions {
		if r.IsHomeRegion {
			result.HomeRegion = r.Name
		}
	}
	for _, region := range regions {
		// region.Key 是三字母码（如 TYO），区域 ID 要用 region.Name（如 ap-tokyo-1）
		regionId := region.Name
		if regionId == "" {
			regionId = region.RegionKey
		}
		rc := c.WithRegion(regionId)
		subs, err := ListCompartments(rc)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", regionId, ErrInfo(err)))
			continue
		}
		// ListCompartments 不返回根 compartment（tenancy 本身），必须手动补上
		compartments := []Compartment{{ID: c.TenancyOcid, Name: "(根)"}}
		compartments = append(compartments, subs...)
		for _, compartment := range compartments {
			instances, err := listInstancesInCompartment(rc, compartment.ID)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s/%s: %s", regionId, compartment.Name, ErrInfo(err)))
				continue
			}
			for _, inst := range instances {
				var vnic *core.Vnic
				if v, err := GetPrimaryVnic(rc, str(inst.Id), compartment.ID); err == nil {
					vnic = v
				}
				var bv *core.BootVolume
				if b, err := GetBootVolume(rc, str(inst.Id), compartment.ID); err == nil {
					bv = b
				}
				result.Raws = append(result.Raws, toRaw(regionId, inst, vnic, bv))
			}
		}
	}
	result.RegionCount = len(regions)
	return result, nil
}

// ============================================================
// 实例操作
// ============================================================

// OpResult 通用操作结果
type OpResult struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	State string `json:"state,omitempty"`
}

func instanceAction(c Creds, instanceId, action string) OpResult {
	ctx := context.Background()
	cmp, err := NewComputeClient(c)
	if err != nil {
		return OpResult{Ok: false, Error: err.Error()}
	}
	resp, err := cmp.InstanceAction(ctx, core.InstanceActionRequest{
		InstanceId: &instanceId,
		Action:     core.InstanceActionActionEnum(action),
	})
	if err != nil {
		return OpResult{Ok: false, Error: ErrInfo(err)}
	}
	return OpResult{Ok: true, State: string(resp.Instance.LifecycleState)}
}

func StopInstance(c Creds, instanceId string) OpResult {
	return instanceAction(c, instanceId, "SOFTSTOP")
}

func StartInstance(c Creds, instanceId string) OpResult {
	return instanceAction(c, instanceId, "START")
}

// UpdateInstanceName 修改实例名称（Oracle 后台的 displayName）
func UpdateInstanceName(c Creds, instanceId, displayName string) OpResult {
	ctx := context.Background()
	cmp, err := NewComputeClient(c)
	if err != nil {
		return OpResult{Ok: false, Error: err.Error()}
	}
	resp, err := cmp.UpdateInstance(ctx, core.UpdateInstanceRequest{
		InstanceId:           &instanceId,
		UpdateInstanceDetails: core.UpdateInstanceDetails{DisplayName: &displayName},
	})
	if err != nil {
		return OpResult{Ok: false, Error: ErrInfo(err)}
	}
	return OpResult{Ok: true, State: string(resp.Instance.LifecycleState)}
}

// UpdateInstanceShape 修改配置（CPU/内存，仅 Flex 形状，需 STOPPED 状态）
func UpdateInstanceShape(c Creds, instanceId string, ocpus, memoryInGBs float64) OpResult {
	ctx := context.Background()
	cmp, err := NewComputeClient(c)
	if err != nil {
		return OpResult{Ok: false, Error: err.Error()}
	}
	resp, err := cmp.UpdateInstance(ctx, core.UpdateInstanceRequest{
		InstanceId: &instanceId,
		UpdateInstanceDetails: core.UpdateInstanceDetails{
			ShapeConfig: &core.UpdateInstanceShapeConfigDetails{
				Ocpus:      common.Float32(float32(ocpus)),
				MemoryInGBs: common.Float32(float32(memoryInGBs)),
			},
		},
	})
	if err != nil {
		return OpResult{Ok: false, Error: ErrInfo(err)}
	}
	return OpResult{Ok: true, State: string(resp.Instance.LifecycleState)}
}

// UpdateBootVolumeVpu 调整引导卷 VPU（合法值 0/10/20/.../120）
func UpdateBootVolumeVpu(c Creds, bootVolumeId string, vpusPerGB float64) OpResult {
	ctx := context.Background()
	bs, err := NewBlockstorageClient(c)
	if err != nil {
		return OpResult{Ok: false, Error: err.Error()}
	}
	vpu := int64(vpusPerGB)
	resp, err := bs.UpdateBootVolume(ctx, core.UpdateBootVolumeRequest{
		BootVolumeId: &bootVolumeId,
		UpdateBootVolumeDetails: core.UpdateBootVolumeDetails{VpusPerGB: &vpu},
	})
	if err != nil {
		return OpResult{Ok: false, Error: ErrInfo(err)}
	}
	_ = resp
	return OpResult{Ok: true}
}

// ChangeIpResult 切换公网 IP 结果
type ChangeIpResult struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	OldIp string `json:"oldIp,omitempty"`
	NewIp string `json:"newIp,omitempty"`
}

// ChangePublicIp 切换 IPv4：主 VNIC → 私网 IP → 查当前绑定的公网 IP → 删除 →
// 轮询等待解绑生效 → 新建 ephemeral 公网 IP（409/429 自动重试）
func ChangePublicIp(c Creds, instanceId, compartmentId string) ChangeIpResult {
	ctx := context.Background()
	cmp, err := NewComputeClient(c)
	if err != nil {
		return ChangeIpResult{Error: err.Error()}
	}
	net, err := NewNetworkClient(c)
	if err != nil {
		return ChangeIpResult{Error: err.Error()}
	}

	// 1) 主 VNIC
	vnic, err := func() (*core.Vnic, error) {
		resp, err := cmp.ListVnicAttachments(ctx, core.ListVnicAttachmentsRequest{
			InstanceId: &instanceId, CompartmentId: &compartmentId,
		})
		if err != nil {
			return nil, err
		}
		for _, att := range resp.Items {
			if att.VnicId == nil {
				continue
			}
			v, err := net.GetVnic(ctx, core.GetVnicRequest{VnicId: att.VnicId})
			if err != nil {
				continue
			}
			if v.Vnic.IsPrimary != nil && *v.Vnic.IsPrimary {
				vv := v.Vnic
				return &vv, nil
			}
		}
		for _, att := range resp.Items {
			if att.VnicId == nil {
				continue
			}
			v, err := net.GetVnic(ctx, core.GetVnicRequest{VnicId: att.VnicId})
			if err != nil {
				continue
			}
			vv := v.Vnic
			return &vv, nil
		}
		return nil, fmt.Errorf("未找到实例的 VNIC")
	}()
	if err != nil {
		return ChangeIpResult{Error: ErrInfo(err)}
	}
	oldIp := str(vnic.PublicIp)

	// 2) 主私网 IP 的 OCID
	privateIps, err := net.ListPrivateIps(ctx, core.ListPrivateIpsRequest{VnicId: vnic.Id})
	if err != nil {
		return ChangeIpResult{Error: ErrInfo(err)}
	}
	var primary *core.PrivateIp
	for i := range privateIps.Items {
		if privateIps.Items[i].IsPrimary != nil && *privateIps.Items[i].IsPrimary {
			primary = &privateIps.Items[i]
			break
		}
	}
	if primary == nil && len(privateIps.Items) > 0 {
		primary = &privateIps.Items[0]
	}
	if primary == nil {
		return ChangeIpResult{Error: "未找到主私网 IP"}
	}

	// 3) 精确查询该私网 IP 当前绑定的公网 IP（未绑定时 404）
	getAssigned := func() *core.PublicIp {
		resp, err := net.GetPublicIpByPrivateIpId(ctx, core.GetPublicIpByPrivateIpIdRequest{
			GetPublicIpByPrivateIpIdDetails: core.GetPublicIpByPrivateIpIdDetails{PrivateIpId: primary.Id},
		})
		if err != nil {
			if StatusCode(err) == 404 {
				return nil
			}
			return nil // 查询失败按未绑定处理，后续有兜底
		}
		p := resp.PublicIp
		return &p
	}

	assigned := getAssigned()

	// 兜底：按地址在列表中查找（对齐 Java 版）
	if assigned == nil && oldIp != "" {
		for _, lifetime := range []core.ListPublicIpsLifetimeEnum{
			core.ListPublicIpsLifetimeEphemeral, core.ListPublicIpsLifetimeReserved,
		} {
			compartmentId := c.TenancyOcid
			list, err := net.ListPublicIps(ctx, core.ListPublicIpsRequest{
				CompartmentId: &compartmentId,
				Scope:         core.ListPublicIpsScopeRegion,
				Lifetime:      lifetime,
			})
			if err != nil {
				continue
			}
			for i := range list.Items {
				if str(list.Items[i].IpAddress) == oldIp {
					p := list.Items[i]
					assigned = &p
					break
				}
			}
			if assigned != nil {
				break
			}
		}
	}

	// 4) 删除旧公网 IP，轮询等待解绑生效
	if assigned != nil {
		if _, err := net.DeletePublicIp(ctx, core.DeletePublicIpRequest{PublicIpId: assigned.Id}); err != nil {
			return ChangeIpResult{Error: ErrInfo(err)}
		}
		released := false
		for i := 0; i < 12; i++ {
			sleep(5000)
			if getAssigned() == nil {
				released = true
				break
			}
		}
		if !released {
			return ChangeIpResult{Error: fmt.Sprintf("旧公网 IP（%s）删除后 60s 仍未解绑，请稍后重试", orDefault(str(assigned.IpAddress), oldIp))}
		}
	}

	// 5) 创建新的 ephemeral 公网 IP；409/429 自动重试
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			sleep(5000 + attempt*1000)
		}
		compartmentId := c.TenancyOcid
		created, err := net.CreatePublicIp(ctx, core.CreatePublicIpRequest{
			CreatePublicIpDetails: core.CreatePublicIpDetails{
				CompartmentId: &compartmentId,
				Lifetime:      core.CreatePublicIpDetailsLifetimeEphemeral,
				PrivateIpId:   primary.Id,
			},
		})
		if err == nil {
			return ChangeIpResult{Ok: true, OldIp: oldIp, NewIp: str(created.PublicIp.IpAddress)}
		}
		lastErr = err
		if code := StatusCode(err); code != 409 && code != 429 {
			break
		}
	}
	return ChangeIpResult{Error: ErrInfo(lastErr)}
}

func orDefault(v, def string) string {
	if v != "" {
		return v
	}
	return def
}
