package ociutil

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// ============================================================
// 安全规则（Security List）管理，逻辑对齐 Node 版 oci-client.js
// ============================================================

var protocolMap = map[string]string{"all": "all", "icmp": "1", "tcp": "6", "udp": "17"}
var protocolReverse = map[string]string{"all": "所有协议", "1": "ICMP", "6": "TCP", "17": "UDP"}

func protocolLabel(p string) string {
	if p == "" {
		return "-"
	}
	if l, ok := protocolReverse[p]; ok {
		return l
	}
	return p
}

// RuleView 前端扁平化的规则视图
type RuleView struct {
	GlobalIndex      int             `json:"globalIndex"`
	LocalIndex       int             `json:"localIndex"`
	SecurityListId   string          `json:"securityListId"`
	SecurityListName string          `json:"securityListName"`
	Protocol         string          `json:"protocol"`
	ProtocolLabel    string          `json:"protocolLabel"`
	Source           string          `json:"source,omitempty"`
	Destination      string          `json:"destination,omitempty"`
	SourceType       string          `json:"sourceType,omitempty"`
	Port             string          `json:"port"`
	IcmpType         *int            `json:"icmpType"`
	Description      string          `json:"description"`
	Raw              json.RawMessage `json:"raw"`
}

// SecurityListInfo Security List 元数据
type SecurityListInfo struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

// SecurityRulesResult 规则列表
type SecurityRulesResult struct {
	Ok            bool               `json:"ok"`
	Error         string             `json:"error,omitempty"`
	Ingress       []RuleView         `json:"ingress"`
	Egress        []RuleView         `json:"egress"`
	SecurityLists []SecurityListInfo `json:"securityLists"`
}

func newNetwork(c Creds) (core.VirtualNetworkClient, error) {
	return NewNetworkClient(c)
}

// ListSecurityRules 列出所有 Security List 及其规则（合并成扁平数组）
func ListSecurityRules(c Creds, compartmentId string) SecurityRulesResult {
	ctx := context.Background()
	result := SecurityRulesResult{
		Ingress:       []RuleView{},
		Egress:        []RuleView{},
		SecurityLists: []SecurityListInfo{},
	}
	net, err := newNetwork(c)
	if err != nil {
		return SecurityRulesResult{Error: err.Error()}
	}
	cmpId := compartmentId
	if cmpId == "" {
		cmpId = c.TenancyOcid
	}
	resp, err := net.ListSecurityLists(ctx, core.ListSecurityListsRequest{CompartmentId: &cmpId})
	if err != nil {
		return SecurityRulesResult{Error: ErrInfo(err)}
	}
	for _, sl := range resp.Items {
		result.SecurityLists = append(result.SecurityLists, SecurityListInfo{ID: str(sl.Id), DisplayName: str(sl.DisplayName)})
		globalIdx := 0
		for i, r := range sl.IngressSecurityRules {
			raw, _ := json.Marshal(r)
			result.Ingress = append(result.Ingress, RuleView{
				GlobalIndex:      globalIdx,
				LocalIndex:       i,
				SecurityListId:   str(sl.Id),
				SecurityListName: str(sl.DisplayName),
				Protocol:         str(r.Protocol),
				ProtocolLabel:    protocolLabel(str(r.Protocol)),
				Source:           str(r.Source),
				SourceType:       string(r.SourceType),
				Port:             formatPort(str(r.Protocol), r.IcmpOptions, r.TcpOptions, r.UdpOptions),
				IcmpType:         icmpTypeOf(r.IcmpOptions),
				Description:      str(r.Description),
				Raw:              raw,
			})
			globalIdx++
		}
		for i, r := range sl.EgressSecurityRules {
			raw, _ := json.Marshal(r)
			result.Egress = append(result.Egress, RuleView{
				GlobalIndex:      globalIdx,
				LocalIndex:       i,
				SecurityListId:   str(sl.Id),
				SecurityListName: str(sl.DisplayName),
				Protocol:         str(r.Protocol),
				ProtocolLabel:    protocolLabel(str(r.Protocol)),
				Destination:      str(r.Destination),
				Port:             formatPort(str(r.Protocol), r.IcmpOptions, r.TcpOptions, r.UdpOptions),
				IcmpType:         icmpTypeOf(r.IcmpOptions),
				Description:      str(r.Description),
				Raw:              raw,
			})
			globalIdx++
		}
	}
	result.Ok = true
	return result
}

func icmpTypeOf(o *core.IcmpOptions) *int {
	if o == nil || o.Type == nil {
		return nil
	}
	t := int(*o.Type)
	return &t
}

func formatPort(protocol string, icmp *core.IcmpOptions, tcp *core.TcpOptions, udpOpts *core.UdpOptions) string {
	if protocol == "1" {
		if icmp != nil && icmp.Type != nil {
			return fmt.Sprintf("ICMP type %d", *icmp.Type)
		}
		return "ICMP"
	}
	if protocol == "all" || protocol == "" {
		return "-"
	}
	var pr *core.PortRange
	if tcp != nil && tcp.DestinationPortRange != nil {
		pr = tcp.DestinationPortRange
	}
	if pr == nil && udpOpts != nil && udpOpts.DestinationPortRange != nil {
		pr = udpOpts.DestinationPortRange
	}
	if pr == nil {
		return "-"
	}
	if pr.Min != nil && pr.Max != nil && *pr.Min == *pr.Max {
		return strconv.Itoa(int(*pr.Min))
	}
	min, max := 0, 0
	if pr.Min != nil {
		min = int(*pr.Min)
	}
	if pr.Max != nil {
		max = int(*pr.Max)
	}
	return fmt.Sprintf("%d-%d", min, max)
}

// RuleInput 前端提交的规则
type RuleInput struct {
	Direction    string
	Source       string
	Destination  string
	Protocol     string
	PortMin      string
	PortMax      string
	IcmpType     string
	Description  string
	SourceType   string
}

// buildIngress / buildEgress 把前端规则转成 SDK 对象
func buildIngress(rule RuleInput) core.IngressSecurityRule {
	protocol := protocolMap[rule.Protocol]
	if protocol == "" {
		protocol = rule.Protocol
	}
	r := core.IngressSecurityRule{
		Protocol:    &protocol,
		Description: optionalStr(rule.Description),
		Source:      common.String(orDefault(rule.Source, "0.0.0.0/0")),
	}
	st := core.IngressSecurityRuleSourceTypeEnum(orDefault(rule.SourceType, "CIDR_BLOCK"))
	r.SourceType = st
	applyOptions(rule, &r.IcmpOptions, &r.TcpOptions, &r.UdpOptions)
	return r
}

func buildEgress(rule RuleInput) core.EgressSecurityRule {
	protocol := protocolMap[rule.Protocol]
	if protocol == "" {
		protocol = rule.Protocol
	}
	r := core.EgressSecurityRule{
		Protocol:    &protocol,
		Description: optionalStr(rule.Description),
		Destination: common.String(orDefault(orDefault(rule.Destination, rule.Source), "0.0.0.0/0")),
	}
	dt := core.EgressSecurityRuleDestinationTypeEnum(orDefault(rule.SourceType, "CIDR_BLOCK"))
	r.DestinationType = dt
	applyOptions(rule, &r.IcmpOptions, &r.TcpOptions, &r.UdpOptions)
	return r
}

func optionalStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func applyOptions(rule RuleInput, icmp **core.IcmpOptions, tcp **core.TcpOptions, udp **core.UdpOptions) {
	protocol := protocolMap[rule.Protocol]
	if protocol == "" {
		protocol = rule.Protocol
	}
	if protocol == "1" {
		t := 0
		if v, err := strconv.Atoi(rule.IcmpType); err == nil {
			t = v
		}
		*icmp = &core.IcmpOptions{Type: &t}
		return
	}
	if protocol == "all" {
		return
	}
	min, err := strconv.Atoi(rule.PortMin)
	if err != nil || min == 0 {
		return
	}
	max := min
	if v, err := strconv.Atoi(rule.PortMax); err == nil && v > 0 {
		max = v
	}
	portRange := core.PortRange{Min: &min, Max: &max}
	if protocol == "6" {
		*tcp = &core.TcpOptions{DestinationPortRange: &portRange}
	} else if protocol == "17" {
		*udp = &core.UdpOptions{DestinationPortRange: &portRange}
	}
}

// 判断两条规则是否相同（去重用）
func ingressEqual(a core.IngressSecurityRule, b core.IngressSecurityRule) bool {
	if str(a.Protocol) != str(b.Protocol) || str(a.Source) != str(b.Source) {
		return false
	}
	return portOptsEqual(str(a.Protocol), a.IcmpOptions, a.TcpOptions, a.UdpOptions,
		b.IcmpOptions, b.TcpOptions, b.UdpOptions)
}

func egressEqual(a core.EgressSecurityRule, b core.EgressSecurityRule) bool {
	if str(a.Protocol) != str(b.Protocol) || str(a.Destination) != str(b.Destination) {
		return false
	}
	return portOptsEqual(str(a.Protocol), a.IcmpOptions, a.TcpOptions, a.UdpOptions,
		b.IcmpOptions, b.TcpOptions, b.UdpOptions)
}

func portOptsEqual(protocol string, icmpA, tcpA, udpA interface{}, icmpB, tcpB, udpB interface{}) bool {
	ia, iokA := icmpA.(*core.IcmpOptions)
	ib, iokB := icmpB.(*core.IcmpOptions)
	if protocol == "all" {
		return true
	}
	if protocol == "1" {
		var ta, tb = -1, -1
		if iokA && ia != nil && ia.Type != nil {
			ta = int(*ia.Type)
		}
		if iokB && ib != nil && ib.Type != nil {
			tb = int(*ib.Type)
		}
		return ta == tb
	}
	pa := destPortRange(tcpA, udpA)
	pb := destPortRange(tcpB, udpB)
	if pa == nil && pb == nil {
		return true
	}
	if pa == nil || pb == nil {
		return false
	}
	amin, amax, bmin, bmax := 0, 0, 0, 0
	if pa.Min != nil {
		amin = int(*pa.Min)
	}
	if pa.Max != nil {
		amax = int(*pa.Max)
	}
	if pb.Min != nil {
		bmin = int(*pb.Min)
	}
	if pb.Max != nil {
		bmax = int(*pb.Max)
	}
	return amin == bmin && amax == bmax
}

func destPortRange(tcp, udp interface{}) *core.PortRange {
	if t, ok := tcp.(*core.TcpOptions); ok && t != nil && t.DestinationPortRange != nil {
		return t.DestinationPortRange
	}
	if u, ok := udp.(*core.UdpOptions); ok && u != nil && u.DestinationPortRange != nil {
		return u.DestinationPortRange
	}
	return nil
}

// getSecurityListFull 拿现有 SecurityList（含完整规则）
func getSecurityListFull(ctx context.Context, net core.VirtualNetworkClient, securityListId string) (ingress []core.IngressSecurityRule, egress []core.EgressSecurityRule, err error) {
	resp, err := net.GetSecurityList(ctx, core.GetSecurityListRequest{SecurityListId: &securityListId})
	if err != nil {
		return nil, nil, err
	}
	return append([]core.IngressSecurityRule{}, resp.SecurityList.IngressSecurityRules...), append([]core.EgressSecurityRule{}, resp.SecurityList.EgressSecurityRules...), nil
}

func commitSecurityList(ctx context.Context, net core.VirtualNetworkClient, securityListId string, ingress []core.IngressSecurityRule, egress []core.EgressSecurityRule) error {
	_, err := net.UpdateSecurityList(ctx, core.UpdateSecurityListRequest{
		SecurityListId: &securityListId,
		UpdateSecurityListDetails: core.UpdateSecurityListDetails{
			IngressSecurityRules: ingress,
			EgressSecurityRules:  egress,
		},
	})
	return err
}

// AddSecurityRule 添加安全规则（同规则自动去重替换）
func AddSecurityRule(c Creds, securityListId string, rule RuleInput) OpResult {
	ctx := context.Background()
	net, err := newNetwork(c)
	if err != nil {
		return OpResult{Error: err.Error()}
	}
	ingress, egress, err := getSecurityListFull(ctx, net, securityListId)
	if err != nil {
		return OpResult{Error: ErrInfo(err)}
	}
	if rule.Direction == "ingress" {
		newRule := buildIngress(rule)
		for i, r := range ingress {
			if ingressEqual(r, newRule) {
				ingress = append(ingress[:i], ingress[i+1:]...)
				break
			}
		}
		ingress = append(ingress, newRule)
	} else {
		newRule := buildEgress(rule)
		for i, r := range egress {
			if egressEqual(r, newRule) {
				egress = append(egress[:i], egress[i+1:]...)
				break
			}
		}
		egress = append(egress, newRule)
	}
	if err := commitSecurityList(ctx, net, securityListId, ingress, egress); err != nil {
		return OpResult{Error: ErrInfo(err)}
	}
	return OpResult{Ok: true}
}

// DeleteSecurityRule 删除安全规则（按 direction + localIndex）
func DeleteSecurityRule(c Creds, securityListId, direction string, localIndex int) OpResult {
	ctx := context.Background()
	net, err := newNetwork(c)
	if err != nil {
		return OpResult{Error: err.Error()}
	}
	ingress, egress, err := getSecurityListFull(ctx, net, securityListId)
	if err != nil {
		return OpResult{Error: ErrInfo(err)}
	}
	if direction == "ingress" {
		if localIndex < 0 || localIndex >= len(ingress) {
			return OpResult{Error: "规则索引越界"}
		}
		ingress = append(ingress[:localIndex], ingress[localIndex+1:]...)
	} else {
		if localIndex < 0 || localIndex >= len(egress) {
			return OpResult{Error: "规则索引越界"}
		}
		egress = append(egress[:localIndex], egress[localIndex+1:]...)
	}
	if err := commitSecurityList(ctx, net, securityListId, ingress, egress); err != nil {
		return OpResult{Error: ErrInfo(err)}
	}
	return OpResult{Ok: true}
}

// UpdateSecurityRule 编辑安全规则
func UpdateSecurityRule(c Creds, securityListId, direction string, localIndex int, rule RuleInput) OpResult {
	ctx := context.Background()
	net, err := newNetwork(c)
	if err != nil {
		return OpResult{Error: err.Error()}
	}
	ingress, egress, err := getSecurityListFull(ctx, net, securityListId)
	if err != nil {
		return OpResult{Error: ErrInfo(err)}
	}
	if direction == "ingress" {
		if localIndex < 0 || localIndex >= len(ingress) {
			return OpResult{Error: "规则索引越界"}
		}
		ingress[localIndex] = buildIngress(rule)
	} else {
		if localIndex < 0 || localIndex >= len(egress) {
			return OpResult{Error: "规则索引越界"}
		}
		egress[localIndex] = buildEgress(rule)
	}
	if err := commitSecurityList(ctx, net, securityListId, ingress, egress); err != nil {
		return OpResult{Error: ErrInfo(err)}
	}
	return OpResult{Ok: true}
}

// ============================================================
// IPv6 管理（翻译自 Node 版，即 oci-start 的 OciIpv6Utils.java）
// ============================================================

// Ipv6Result IPv6 操作结果
type Ipv6Result struct {
	Ok         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	Ipv6       string `json:"ipv6,omitempty"`
	SubnetCidr string `json:"subnetCidr,omitempty"`
}

func listVnicIpv6s(ctx context.Context, net core.VirtualNetworkClient, vnicId string) ([]core.Ipv6, error) {
	r, err := net.ListIpv6s(ctx, core.ListIpv6sRequest{VnicId: &vnicId})
	if err != nil {
		return nil, err
	}
	return r.Items, nil
}

// ensureVcnIpv6Cidr 确保 VCN 有 IPv6 CIDR（没有就加一个，OCI 自动分配 /56）
func ensureVcnIpv6Cidr(ctx context.Context, net core.VirtualNetworkClient, vcnId string) (*core.Vcn, error) {
	resp, err := net.GetVcn(ctx, core.GetVcnRequest{VcnId: &vcnId})
	if err != nil {
		return nil, err
	}
	if len(resp.Vcn.Ipv6CidrBlocks) > 0 {
		v := resp.Vcn
		return &v, nil
	}
	if _, err := net.AddIpv6VcnCidr(ctx, core.AddIpv6VcnCidrRequest{
		VcnId:                  &vcnId,
		AddVcnIpv6CidrDetails: core.AddVcnIpv6CidrDetails{},
	}); err != nil {
		return nil, err
	}
	resp2, err := net.GetVcn(ctx, core.GetVcnRequest{VcnId: &vcnId})
	if err != nil {
		return nil, err
	}
	v := resp2.Vcn
	return &v, nil
}

// ensureSubnetIpv6Cidr 确保子网有 IPv6 CIDR（VCN 的 /56 收敛为 /64）
func ensureSubnetIpv6Cidr(ctx context.Context, net core.VirtualNetworkClient, subnetId string) (*core.Subnet, error) {
	resp, err := net.GetSubnet(ctx, core.GetSubnetRequest{SubnetId: &subnetId})
	if err != nil {
		return nil, err
	}
	if resp.Subnet.Ipv6CidrBlock != nil && *resp.Subnet.Ipv6CidrBlock != "" {
		s := resp.Subnet
		return &s, nil
	}
	vcn, err := ensureVcnIpv6Cidr(ctx, net, str(resp.Subnet.VcnId))
	if err != nil {
		return nil, err
	}
	if len(vcn.Ipv6CidrBlocks) == 0 {
		return nil, fmt.Errorf("VCN 没有 IPv6 CIDR 块")
	}
	subnetCidr := strings.ReplaceAll(vcn.Ipv6CidrBlocks[0], "/56", "/64")
	if _, err := net.AddIpv6SubnetCidr(ctx, core.AddIpv6SubnetCidrRequest{
		SubnetId:               &subnetId,
		AddSubnetIpv6CidrDetails: core.AddSubnetIpv6CidrDetails{Ipv6CidrBlock: &subnetCidr},
	}); err != nil {
		return nil, err
	}
	resp2, err := net.GetSubnet(ctx, core.GetSubnetRequest{SubnetId: &subnetId})
	if err != nil {
		return nil, err
	}
	s := resp2.Subnet
	return &s, nil
}

// ensureIpv6InternetGateway 确保 VCN 有可用网关，并给默认路由表补 ::/0 规则
func ensureIpv6InternetGateway(ctx context.Context, net core.VirtualNetworkClient, compartmentId, vcnId string) (string, error) {
	var gatewayId string
	list, err := net.ListInternetGateways(ctx, core.ListInternetGatewaysRequest{
		CompartmentId: &compartmentId, VcnId: &vcnId,
	})
	if err == nil {
		for _, g := range list.Items {
			if g.LifecycleState == core.InternetGatewayLifecycleStateAvailable {
				gatewayId = str(g.Id)
				break
			}
		}
	}
	if gatewayId == "" {
		name := "IPv6-Internet-Gateway-" + strconv.FormatInt(time.Now().UnixMilli(), 10)
		created, err := net.CreateInternetGateway(ctx, core.CreateInternetGatewayRequest{
			CreateInternetGatewayDetails: core.CreateInternetGatewayDetails{
				CompartmentId: &compartmentId,
				VcnId:         &vcnId,
				DisplayName:   &name,
			},
		})
		if err != nil {
			return "", err
		}
		gatewayId = str(created.InternetGateway.Id)
	}
	// 默认路由表补 ::/0
	vcnResp, err := net.GetVcn(ctx, core.GetVcnRequest{VcnId: &vcnId})
	if err != nil {
		return gatewayId, err
	}
	rtResp, err := net.GetRouteTable(ctx, core.GetRouteTableRequest{RtId: vcnResp.Vcn.DefaultRouteTableId})
	if err != nil {
		return gatewayId, err
	}
	rules := rtResp.RouteTable.RouteRules
	hasIpv6Rule := false
	for _, r := range rules {
		if str(r.Destination) == "::/0" {
			hasIpv6Rule = true
			break
		}
	}
	if !hasIpv6Rule {
		rules = append(rules, core.RouteRule{
			Destination:      common.String("::/0"),
			DestinationType:  core.RouteRuleDestinationTypeCidrBlock,
			NetworkEntityId:  &gatewayId,
		})
		if _, err := net.UpdateRouteTable(ctx, core.UpdateRouteTableRequest{
			RtId:                     vcnResp.Vcn.DefaultRouteTableId,
			UpdateRouteTableDetails: core.UpdateRouteTableDetails{RouteRules: rules},
		}); err != nil {
			return gatewayId, err
		}
	}
	return gatewayId, nil
}

// 等待 IPv6 变为 AVAILABLE（2s 轮询，最多 12 次）
func waitForIpv6Available(ctx context.Context, net core.VirtualNetworkClient, ipv6Id string) bool {
	for i := 0; i < 12; i++ {
		sleep(2000)
		r, err := net.GetIpv6(ctx, core.GetIpv6Request{Ipv6Id: &ipv6Id})
		if err == nil && string(r.Ipv6.LifecycleState) == "AVAILABLE" {
			return true
		}
	}
	return false
}

// 等待 IPv6 真正删除（GetIpv6 报错即删除完成）
func waitForIpv6Deleted(ctx context.Context, net core.VirtualNetworkClient, ipv6Id string) bool {
	for i := 0; i < 12; i++ {
		sleep(2000)
		if _, err := net.GetIpv6(ctx, core.GetIpv6Request{Ipv6Id: &ipv6Id}); err != nil {
			return true
		}
	}
	return false
}

// enableVnicIpv6 VNIC 上没有 IPv6 则创建（forceNew 时先删旧再建新的）
func enableVnicIpv6(ctx context.Context, net core.VirtualNetworkClient, vnicId string, forceNewAddress bool) (string, error) {
	existing, err := listVnicIpv6s(ctx, net, vnicId)
	if err != nil {
		return "", err
	}
	if len(existing) > 0 && !forceNewAddress {
		return str(existing[0].IpAddress), nil
	}
	for _, old := range existing {
		if _, err := net.DeleteIpv6(ctx, core.DeleteIpv6Request{Ipv6Id: old.Id}); err != nil {
			continue
		}
		waitForIpv6Deleted(ctx, net, str(old.Id))
	}
	created, err := net.CreateIpv6(ctx, core.CreateIpv6Request{
		CreateIpv6Details: core.CreateIpv6Details{VnicId: &vnicId},
	})
	if err != nil {
		return "", err
	}
	if !waitForIpv6Available(ctx, net, str(created.Ipv6.Id)) {
		return "", fmt.Errorf("IPv6 地址未能进入可用状态（等待 24 秒超时）")
	}
	return str(created.Ipv6.IpAddress), nil
}

// EnableInstanceIpv6 给实例主 VNIC 配置 IPv6（含 VCN/子网/网关/路由的自动准备）
func EnableInstanceIpv6(c Creds, instanceId, compartmentId string, forceNewAddress bool) Ipv6Result {
	ctx := context.Background()
	net, err := newNetwork(c)
	if err != nil {
		return Ipv6Result{Error: err.Error()}
	}
	vnic, err := GetPrimaryVnic(c, instanceId, compartmentId)
	if err != nil || vnic == nil {
		return Ipv6Result{Error: "未找到实例的 VNIC"}
	}
	subnet, err := ensureSubnetIpv6Cidr(ctx, net, str(vnic.SubnetId))
	if err != nil {
		return Ipv6Result{Error: ErrInfo(err)}
	}
	if _, err := ensureIpv6InternetGateway(ctx, net, c.TenancyOcid, str(subnet.VcnId)); err != nil {
		return Ipv6Result{Error: ErrInfo(err)}
	}
	addr, err := enableVnicIpv6(ctx, net, str(vnic.Id), forceNewAddress)
	if err != nil {
		return Ipv6Result{Error: ErrInfo(err)}
	}
	return Ipv6Result{Ok: true, Ipv6: addr, SubnetCidr: str(subnet.Ipv6CidrBlock)}
}

// ChangeInstanceIpv6 删除当前 IPv6 后分配新的
func ChangeInstanceIpv6(c Creds, instanceId, compartmentId string) Ipv6Result {
	return EnableInstanceIpv6(c, instanceId, compartmentId, true)
}
