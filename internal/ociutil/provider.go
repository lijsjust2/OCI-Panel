// Package ociutil 封装 OCI Go SDK：认证 Provider、区域/Compartment 查询、
// 实例同步与操作、安全规则、IPv4/IPv6 切换（逻辑对齐 Node 版 oci-client.js）。
package ociutil

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"

	"oci-panel/internal/cryptoutil"
	"oci-panel/internal/store"
)

// Creds 含解密后私钥的租户凭据
type Creds struct {
	TenancyOcid      string
	UserOcid         string
	Fingerprint      string
	Region           string
	HomeRegion       string
	PrivateKey       string
	Passphrase       string
	AccountCreatedAt string // 开户时间（费用查询截断用）
}

// CredsFromTenant 从 store 租户构造（解密私钥）
func CredsFromTenant(t *store.Tenant) (Creds, error) {
	key, err := cryptoutil.DecryptText(t.PrivateKeyEnc)
	if err != nil {
		return Creds{}, fmt.Errorf("私钥解密失败: %w", err)
	}
	return Creds{
		TenancyOcid: t.TenancyOcid,
		UserOcid:    t.UserOcid,
		Fingerprint: t.Fingerprint,
		Region:      t.Region,
		HomeRegion:  t.HomeRegion,
		PrivateKey:  key,
		Passphrase:  t.Passphrase,
	}, nil
}

// WithRegion 返回改用指定区域的凭据副本
func (c Creds) WithRegion(region string) Creds {
	c.Region = region
	return c
}

// ---- 工具：私钥规范化（粘贴丢失换行时按 64 字符重排） ----

var pemRe = regexp.MustCompile(`-----BEGIN ([A-Z ]*PRIVATE KEY)-----([\s\S]*?)-----END (?:[A-Z ]*PRIVATE KEY)-----`)

func NormalizePrivateKey(key string) string {
	m := pemRe.FindStringSubmatch(key)
	if m == nil {
		return key
	}
	body := regexp.MustCompile(`\s+`).ReplaceAllString(m[2], "")
	if body == "" {
		return key
	}
	var lines []string
	for i := 0; i < len(body); i += 64 {
		end := i + 64
		if end > len(body) {
			end = len(body)
		}
		lines = append(lines, body[i:end])
	}
	return fmt.Sprintf("-----BEGIN %s-----\n%s\n-----END %s-----\n", m[1], strings.Join(lines, "\n"), m[1])
}

func makeProvider(c Creds) (common.ConfigurationProvider, error) {
	if c.PrivateKey == "" {
		return nil, fmt.Errorf("私钥为空，请重新导入 API 密钥")
	}
	key := NormalizePrivateKey(c.PrivateKey)
	var passphrase *string
	if c.Passphrase != "" {
		passphrase = &c.Passphrase
	}
	region := c.Region
	if region == "" {
		region = "us-ashburn-1"
	}
	return common.NewRawConfigurationProvider(c.TenancyOcid, c.UserOcid, region, c.Fingerprint, key, passphrase), nil
}

// ---- 客户端构造 ----

func NewIdentityClient(c Creds) (identity.IdentityClient, error) {
	p, err := makeProvider(c)
	if err != nil {
		return identity.IdentityClient{}, err
	}
	cl, err := identity.NewIdentityClientWithConfigurationProvider(p)
	if err != nil {
		return identity.IdentityClient{}, err
	}
	cl.SetRegion(c.Region)
	return cl, nil
}

func NewComputeClient(c Creds) (core.ComputeClient, error) {
	p, err := makeProvider(c)
	if err != nil {
		return core.ComputeClient{}, err
	}
	cl, err := core.NewComputeClientWithConfigurationProvider(p)
	if err != nil {
		return core.ComputeClient{}, err
	}
	cl.SetRegion(c.Region)
	return cl, nil
}

func NewNetworkClient(c Creds) (core.VirtualNetworkClient, error) {
	p, err := makeProvider(c)
	if err != nil {
		return core.VirtualNetworkClient{}, err
	}
	cl, err := core.NewVirtualNetworkClientWithConfigurationProvider(p)
	if err != nil {
		return core.VirtualNetworkClient{}, err
	}
	cl.SetRegion(c.Region)
	return cl, nil
}

func NewBlockstorageClient(c Creds) (core.BlockstorageClient, error) {
	p, err := makeProvider(c)
	if err != nil {
		return core.BlockstorageClient{}, err
	}
	cl, err := core.NewBlockstorageClientWithConfigurationProvider(p)
	if err != nil {
		return core.BlockstorageClient{}, err
	}
	cl.SetRegion(c.Region)
	return cl, nil
}

// ---- 错误信息（对齐 Node 版 errInfo） ----

func ErrInfo(err error) string {
	if err == nil {
		return ""
	}
	if se, ok := common.IsServiceError(err); ok {
		msg := se.GetMessage()
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Sprintf("OCI API %d [%s]: %s", se.GetHTTPStatusCode(), se.GetCode(), msg)
	}
	msg := err.Error()
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return "OCI API: " + msg
}

// StatusCode 提取服务端状态码（非服务错误返回 0）
func StatusCode(err error) int {
	if se, ok := common.IsServiceError(err); ok {
		return se.GetHTTPStatusCode()
	}
	return 0
}

// ---- 测试连通性 ----

func TestConnection(c Creds) (ok bool, message string) {
	ctx := context.Background()
	idc, err := NewIdentityClient(c)
	if err != nil {
		return false, "构造客户端失败: " + err.Error()
	}
	regions, err := idc.ListRegions(ctx)
	if err != nil {
		return false, "OCI API 返回: " + ErrInfo(err)
	}
	// 对齐 Java 版 checkAccountStatus：认证 OK 后再验证 Compartments 访问
	compartmentId := c.TenancyOcid
	if _, err := idc.ListCompartments(ctx, identity.ListCompartmentsRequest{CompartmentId: &compartmentId}); err != nil {
		return false, "OCI API 返回: " + ErrInfo(err)
	}
	return true, fmt.Sprintf("连接成功，认证/Compartments 访问正常（%d 个区域）", len(regions.Items))
}

// TenancyInfo 租户开户信息（根 compartment）
type TenancyInfo struct {
	AccountCreatedAt string
	AccountState     string
}

func GetTenancyInfo(c Creds) TenancyInfo {
	ctx := context.Background()
	var info TenancyInfo
	idc, err := NewIdentityClient(c)
	if err != nil {
		return info
	}
	compartmentId := c.TenancyOcid
	resp, err := idc.GetCompartment(ctx, identity.GetCompartmentRequest{CompartmentId: &compartmentId})
	if err != nil {
		return info
	}
	if resp.Compartment.TimeCreated != nil {
		info.AccountCreatedAt = resp.Compartment.TimeCreated.Format(timeFormatRFC3339Milli)
	}
	if resp.Compartment.LifecycleState != "" {
		info.AccountState = string(resp.Compartment.LifecycleState)
	}
	return info
}

const timeFormatRFC3339Milli = "2006-01-02T15:04:05.000Z07:00"

// RegionInfo 已订阅区域
type RegionInfo struct {
	Key         string
	RegionKey   string
	Name        string
	IsHomeRegion bool
}

// ListSubscribedRegions 已订阅的区域（Ready 状态）；失败回退全量区域列表
func ListSubscribedRegions(c Creds) ([]RegionInfo, error) {
	ctx := context.Background()
	idc, err := NewIdentityClient(c)
	if err != nil {
		return nil, err
	}
	tenancyId := c.TenancyOcid
	sub, err := idc.ListRegionSubscriptions(ctx, identity.ListRegionSubscriptionsRequest{TenancyId: &tenancyId})
	if err == nil && len(sub.Items) > 0 {
		var out []RegionInfo
		for _, s := range sub.Items {
			if s.Status != identity.RegionSubscriptionStatusReady {
				continue
			}
			var isHome bool
			if s.IsHomeRegion != nil {
				isHome = *s.IsHomeRegion
			}
			key, name := str(s.RegionKey), str(s.RegionName)
			out = append(out, RegionInfo{Key: key, RegionKey: key, Name: name, IsHomeRegion: isHome})
		}
		return out, nil
	}
	resp, err := idc.ListRegions(ctx)
	if err != nil {
		return nil, err
	}
	var out []RegionInfo
	for _, r := range resp.Items {
		key := str(r.Key)
		out = append(out, RegionInfo{Key: key, RegionKey: key, Name: str(r.Name)})
	}
	return out, nil
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// Compartment Compartment 列表项
type Compartment struct {
	ID   string
	Name string
}

// ListCompartments 含子 Compartment（只返回 ACTIVE）
func ListCompartments(c Creds) ([]Compartment, error) {
	ctx := context.Background()
	idc, err := NewIdentityClient(c)
	if err != nil {
		return nil, err
	}
	req := identity.ListCompartmentsRequest{
		CompartmentId:          &c.TenancyOcid,
		CompartmentIdInSubtree: common.Bool(true),
		AccessLevel:            identity.ListCompartmentsAccessLevelAny,
		Limit:                  common.Int(100),
	}
	var result []Compartment
	for {
		resp, err := idc.ListCompartments(ctx, req)
		if err != nil {
			return nil, err
		}
		for _, cp := range resp.Items {
			if cp.LifecycleState == identity.CompartmentLifecycleStateActive {
				result = append(result, Compartment{ID: str(cp.Id), Name: str(cp.Name)})
			}
		}
		if resp.OpcNextPage == nil || *resp.OpcNextPage == "" {
			break
		}
		req.Page = resp.OpcNextPage
	}
	return result, nil
}
