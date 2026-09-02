package store

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"oci-panel/internal/config"
	"oci-panel/internal/cryptoutil"
)

var storeFile = filepath.Join(config.DataDir, "store.json")

// Settings 用户设置（含旧 two_fa_* 字段兼容）
type Settings struct {
	BarkURL            string `json:"bark_url,omitempty"`
	BarkKey            string `json:"bark_key,omitempty"`
	PushplusToken      string `json:"pushplus_token,omitempty"`
	NotifyChannel      string `json:"notify_channel,omitempty"`
	NotifyEnabled      bool   `json:"notify_enabled,omitempty"`
	NotifyTime         string `json:"notify_time,omitempty"`
	NotifyCostsDaily   bool   `json:"notify_costs_daily,omitempty"`
	NotifyAccountHealth bool  `json:"notify_account_health,omitempty"`
	NotifyTrafficAlert bool   `json:"notify_traffic_alert,omitempty"`
	TwoFAEnabled       bool   `json:"two_fa_enabled,omitempty"`
	TwoFAChannel       string `json:"two_fa_channel,omitempty"`
	// 旧结构兼容字段
	TwoFAProvider string `json:"two_fa_provider,omitempty"`
	TwoFAToken    string `json:"two_fa_token,omitempty"`
	TwoFABarkURL  string `json:"two_fa_bark_url,omitempty"`
	TwoFABarkKey  string `json:"two_fa_bark_key,omitempty"`
}

type User struct {
	ID           int      `json:"id"`
	Username     string   `json:"username"`
	PasswordHash string   `json:"password_hash"`
	// PasswordEpoch 密码版本号：改密码时递增，用于使改密前的旧会话 Cookie 失效
	PasswordEpoch int      `json:"password_epoch,omitempty"`
	Settings      Settings `json:"settings,omitempty"`
}

type Tenant struct {
	ID                  int      `json:"id"`
	CreatedAt           string   `json:"created_at,omitempty"`
	Name                string   `json:"name"`
	TenancyOcid         string   `json:"tenancy_ocid"`
	UserOcid            string   `json:"user_ocid"`
	Fingerprint         string   `json:"fingerprint"`
	Region              string   `json:"region"`
	PrivateKeyEnc       string   `json:"private_key_enc,omitempty"`
	Passphrase          string   `json:"passphrase,omitempty"`
	CustomName          string   `json:"custom_name,omitempty"`
	Cost                string   `json:"cost,omitempty"`
	AccountType         string   `json:"account_type,omitempty"`
	HomeRegion          string   `json:"home_region,omitempty"`
	MultiRegion         bool     `json:"multi_region,omitempty"`
	RegionCount         int      `json:"region_count,omitempty"`
	InstanceCount       int      `json:"instance_count,omitempty"`
	AccountCreatedAt    string   `json:"account_created_at,omitempty"`
	AccountState        string   `json:"account_state,omitempty"`
	LastSyncAt          string   `json:"last_sync_at,omitempty"`
	SyncStatus          string   `json:"sync_status,omitempty"`
	SyncError           string   `json:"sync_error,omitempty"`
	TrafficEnabled      bool     `json:"traffic_enabled,omitempty"`
	TrafficThreshold    float64  `json:"traffic_threshold,omitempty"`
	TrafficAutoshutdown bool     `json:"traffic_autoshutdown,omitempty"`
	TrafficLastChecked  string   `json:"traffic_last_checked,omitempty"`
	TrafficLastTotalGB  *float64 `json:"traffic_last_total_gb,omitempty"`
	TrafficLastExceeded bool     `json:"traffic_last_exceeded,omitempty"`
	Regions             []string `json:"regions,omitempty"`
}

// Clone 返回去除私钥后的副本
func (t Tenant) Clone() Tenant {
	t.PrivateKeyEnc = ""
	return t
}

type Instance struct {
	ID                int      `json:"id"`
	TenantID          int      `json:"tenant_id"`
	OciID             string   `json:"oci_id"`
	DisplayName       string   `json:"display_name"`
	LifecycleState    string   `json:"lifecycle_state"`
	Shape             string   `json:"shape"`
	Region            string   `json:"region"`
	AvailabilityDomain string   `json:"availability_domain,omitempty"`
	CompartmentID     string   `json:"compartment_id,omitempty"`
	CreatedAt         string   `json:"created_at,omitempty"`
	RunningSince      *string  `json:"running_since,omitempty"`
	PrivateIP         string   `json:"private_ip,omitempty"`
	PublicIP          string   `json:"public_ip,omitempty"`
	IPv6              string   `json:"ipv6,omitempty"`
	OcpuCount         *float64 `json:"ocpu_count,omitempty"`
	MemoryInGBs       *float64 `json:"memory_in_gbs,omitempty"`
	Arch              string   `json:"arch,omitempty"`
	BootVolumeID      string   `json:"boot_volume_id,omitempty"`
	BootVolumeSize    *float64 `json:"boot_volume_size,omitempty"`
	VpusPerGB         *float64 `json:"vpus_per_gb,omitempty"`
	Note              string   `json:"note,omitempty"`
}

// RawInstance 同步时从 OCI 拉到的原始实例（含 VNIC/引导卷补充信息）
type RawInstance struct {
	ID                string   `json:"id"`
	DisplayName       string   `json:"displayName"`
	LifecycleState    string   `json:"lifecycleState"`
	Shape             string   `json:"shape"`
	AvailabilityDomain string   `json:"availabilityDomain"`
	CompartmentID     string   `json:"compartmentId"`
	TimeCreated       string   `json:"timeCreated"`
	Region            string   `json:"_region"`
	PrivateIPs        []string `json:"_private_ips"`
	PublicIPs         []string `json:"_public_ips"`
	IPv6s             []string `json:"_ipv6s"`
	BootVolumeID      string   `json:"_boot_volume_id"`
	BootVolumeSize    *float64 `json:"_boot_volume_size"`
	VpusPerGB         *float64 `json:"_vpus_per_gb"`
	Ocpus             *float64 `json:"ocpus"`
	MemoryInGBs       *float64 `json:"memoryInGBs"`
	Arch              string   `json:"arch"`
}

type DailyCost struct {
	Compute   float64 `json:"compute"`
	Storage   float64 `json:"storage"`
	Network   float64 `json:"network"`
	Other     float64 `json:"other"`
	Total     float64 `json:"total"`
	Currency  string  `json:"currency"`
	UpdatedAt string  `json:"updated_at,omitempty"`
}

type dataFile struct {
	Users          []User                        `json:"users"`
	Tenants        []Tenant                      `json:"tenants"`
	Instances      []Instance                    `json:"instances"`
	Costs          map[string]map[string]DailyCost `json:"costs"`
	NextTenantID   int                           `json:"nextTenantId"`
	NextInstanceID int                           `json:"nextInstanceId"`
}

var (
	mu   sync.Mutex
	data *dataFile
)

func save() {
	tmp := storeFile + ".tmp"
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Println("[存储] 序列化失败:", err)
		return
	}
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		fmt.Println("[存储] 写入失败（数据仅保留在内存中，重启后将丢失）:", err)
		return
	}
	if err := os.Rename(tmp, storeFile); err != nil {
		fmt.Println("[存储] 替换 store.json 失败:", err)
	}
}

func Init() {
	mu.Lock()
	defer mu.Unlock()
	data = &dataFile{NextTenantID: 1, NextInstanceID: 1}
	if b, err := os.ReadFile(storeFile); err == nil {
		var d dataFile
		if err := json.Unmarshal(b, &d); err != nil {
			_ = os.Rename(storeFile, fmt.Sprintf("%s.bak.%d", storeFile, time.Now().Unix()))
		} else {
			data = &d
		}
	}
	if data.Instances == nil {
		data.Instances = []Instance{}
	}
	if data.Costs == nil {
		data.Costs = map[string]map[string]DailyCost{}
	}
	if data.NextInstanceID == 0 {
		data.NextInstanceID = 1
	}
	if data.NextTenantID == 0 {
		data.NextTenantID = 1
	}
	// ADMIN_PASSWORD 环境变量创建初始管理员（仅数据为空时）
	if len(data.Users) == 0 {
		if pw := os.Getenv("ADMIN_PASSWORD"); pw != "" {
			if h, err := cryptoutil.HashPassword(pw); err == nil {
				data.Users = append(data.Users, User{ID: 1, Username: "admin", PasswordHash: h})
				save()
				fmt.Println("[初始化] 已通过 ADMIN_PASSWORD 环境变量创建管理员账号 admin")
			}
		}
	}
}

// ---- 用户 ----

func HasUser() bool {
	mu.Lock()
	defer mu.Unlock()
	return len(data.Users) > 0
}

func ListUsers() []User {
	mu.Lock()
	defer mu.Unlock()
	out := make([]User, len(data.Users))
	copy(out, data.Users)
	return out
}

func FindUser(username string) *User {
	mu.Lock()
	defer mu.Unlock()
	for i := range data.Users {
		if data.Users[i].Username == username {
			u := data.Users[i]
			return &u
		}
	}
	return nil
}

func CreateUser(username, passwordHash string) bool {
	mu.Lock()
	defer mu.Unlock()
	for _, u := range data.Users {
		if u.Username == username {
			return false
		}
	}
	data.Users = append(data.Users, User{ID: len(data.Users) + 1, Username: username, PasswordHash: passwordHash})
	save()
	return true
}

func UpdateUserPassword(username, newHash string) bool {
	mu.Lock()
	defer mu.Unlock()
	for i := range data.Users {
		if data.Users[i].Username == username {
			data.Users[i].PasswordHash = newHash
			data.Users[i].PasswordEpoch++
			save()
			return true
		}
	}
	return false
}

// GetUserSettings 返回规范化后的设置（兼容旧字段 + 默认值，逻辑对齐 Node 版）
func GetUserSettings(username string) Settings {
	u := FindUser(username)
	if u == nil {
		return defaultSettings()
	}
	s := u.Settings
	e := defaultSettings()
	// 兼容：旧 two_fa_* 字段迁移为公共字段
	if e.BarkURL == "" {
		e.BarkURL = s.TwoFABarkURL
	}
	if e.BarkKey == "" {
		e.BarkKey = s.TwoFABarkKey
	}
	if e.PushplusToken == "" {
		e.PushplusToken = s.TwoFAToken
	}
	e.NotifyChannel = orDefault(s.NotifyChannel, orDefault(s.TwoFAProvider, "bark"))
	e.TwoFAChannel = orDefault(s.TwoFAChannel, orDefault(s.TwoFAProvider, e.NotifyChannel))
	e.TwoFAEnabled = s.TwoFAEnabled
	e.BarkURL = orDefault(s.BarkURL, e.BarkURL)
	e.BarkKey = orDefault(s.BarkKey, e.BarkKey)
	e.PushplusToken = orDefault(s.PushplusToken, e.PushplusToken)
	e.NotifyEnabled = s.NotifyEnabled
	e.NotifyTime = orDefault(s.NotifyTime, "09:00")
	e.NotifyCostsDaily = s.NotifyCostsDaily
	e.NotifyAccountHealth = s.NotifyAccountHealth
	e.NotifyTrafficAlert = s.NotifyTrafficAlert
	return e
}

func defaultSettings() Settings {
	return Settings{NotifyTime: "09:00", NotifyChannel: "bark", TwoFAChannel: "bark"}
}

func orDefault(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func UpdateUserSettings(username string, patch func(*Settings)) bool {
	mu.Lock()
	defer mu.Unlock()
	for i := range data.Users {
		if data.Users[i].Username == username {
			patch(&data.Users[i].Settings)
			save()
			return true
		}
	}
	return false
}

// ---- 租户 ----

func ListTenants() []Tenant {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Tenant, 0, len(data.Tenants))
	for _, t := range data.Tenants {
		out = append(out, t.Clone())
	}
	return out
}

func GetTenant(id int) *Tenant {
	mu.Lock()
	defer mu.Unlock()
	for i := range data.Tenants {
		if data.Tenants[i].ID == id {
			t := data.Tenants[i]
			return &t
		}
	}
	return nil
}

// GetTenantWithKey 返回含加密私钥的租户
func GetTenantWithKey(id int) *Tenant {
	return GetTenant(id) // Clone() 已去掉私钥，这里单独取原始记录
}

func getTenantRaw(id int) *Tenant {
	for i := range data.Tenants {
		if data.Tenants[i].ID == id {
			return &data.Tenants[i]
		}
	}
	return nil
}

func AddTenant(t Tenant) int {
	mu.Lock()
	defer mu.Unlock()
	t.ID = data.NextTenantID
	data.NextTenantID++
	t.CreatedAt = time.Now().Format("2006/1/2 15:04:05")
	data.Tenants = append(data.Tenants, t)
	save()
	return t.ID
}

func DeleteTenant(id int) {
	mu.Lock()
	defer mu.Unlock()
	tenants := data.Tenants[:0]
	for _, t := range data.Tenants {
		if t.ID != id {
			tenants = append(tenants, t)
		}
	}
	data.Tenants = tenants
	instances := data.Instances[:0]
	for _, i := range data.Instances {
		if i.TenantID != id {
			instances = append(instances, i)
		}
	}
	data.Instances = instances
	delete(data.Costs, fmt.Sprintf("%d", id))
	save()
}

// SyncInfo 同步结果回填
type SyncInfo struct {
	Status           string
	Error            string
	HomeRegion       string
	MultiRegion      bool
	RegionCount      int
	InstanceCount    int
	AccountCreatedAt string
	AccountState     string
}

func UpdateTenantSyncInfo(id int, info SyncInfo) {
	mu.Lock()
	defer mu.Unlock()
	t := getTenantRaw(id)
	if t == nil {
		return
	}
	t.LastSyncAt = time.Now().Format("2006/1/2 15:04:05")
	t.SyncStatus = info.Status
	if info.Error != "" {
		t.SyncError = info.Error
	} else {
		t.SyncError = ""
	}
	if info.HomeRegion != "" {
		t.HomeRegion = info.HomeRegion
	}
	t.MultiRegion = info.MultiRegion
	t.RegionCount = info.RegionCount
	t.InstanceCount = info.InstanceCount
	if info.AccountCreatedAt != "" {
		if ts, err := time.Parse(time.RFC3339, info.AccountCreatedAt); err == nil {
			t.AccountCreatedAt = ts.UTC().Format(time.RFC3339)
		} else {
			t.AccountCreatedAt = info.AccountCreatedAt
		}
	}
	if info.AccountState != "" {
		t.AccountState = info.AccountState
	}
	save()
}

// TenantFields 编辑租户字段（字段为指针时才更新，逻辑对齐 Node 版）
type TenantFields struct {
	Name                *string
	TenancyOcid         *string
	UserOcid            *string
	Fingerprint         *string
	Region              *string
	PrivateKeyEnc       *string
	CustomName          *string
	Cost                *string
	AccountType         *string
	TrafficEnabled      *bool
	TrafficThreshold    *float64
	TrafficAutoshutdown *bool
	TrafficLastChecked  *string
	TrafficLastTotalGB  *float64
	TrafficLastExceeded *bool
}

func UpdateTenantFields(id int, f TenantFields) *Tenant {
	mu.Lock()
	defer mu.Unlock()
	t := getTenantRaw(id)
	if t == nil {
		return nil
	}
	set := func(dst *string, v *string, requireNonEmpty bool) {
		if v == nil {
			return
		}
		if requireNonEmpty && *v == "" {
			return
		}
		*dst = *v
	}
	set(&t.Name, f.Name, true)
	set(&t.TenancyOcid, f.TenancyOcid, true)
	set(&t.UserOcid, f.UserOcid, true)
	set(&t.Fingerprint, f.Fingerprint, true)
	set(&t.Region, f.Region, true)
	set(&t.PrivateKeyEnc, f.PrivateKeyEnc, true)
	set(&t.CustomName, f.CustomName, false)
	set(&t.Cost, f.Cost, false)
	set(&t.AccountType, f.AccountType, false)
	set(&t.TrafficLastChecked, f.TrafficLastChecked, false)
	if f.TrafficEnabled != nil {
		t.TrafficEnabled = *f.TrafficEnabled
	}
	if f.TrafficThreshold != nil {
		v := *f.TrafficThreshold
		if v == 0 {
			v = 9000
		}
		t.TrafficThreshold = v
	}
	if f.TrafficAutoshutdown != nil {
		t.TrafficAutoshutdown = *f.TrafficAutoshutdown
	}
	if f.TrafficLastTotalGB != nil {
		t.TrafficLastTotalGB = f.TrafficLastTotalGB
	}
	if f.TrafficLastExceeded != nil {
		t.TrafficLastExceeded = *f.TrafficLastExceeded
	}
	save()
	out := t.Clone()
	return &out
}

// ---- 实例 ----

func ListInstances(tenantID int) []Instance {
	mu.Lock()
	defer mu.Unlock()
	var out []Instance
	for _, i := range data.Instances {
		if tenantID == 0 || i.TenantID == tenantID {
			out = append(out, i)
		}
	}
	return out
}

func GetInstance(id int) *Instance {
	mu.Lock()
	defer mu.Unlock()
	for i := range data.Instances {
		if data.Instances[i].ID == id {
			inst := data.Instances[i]
			return &inst
		}
	}
	return nil
}

func ReplaceTenantInstances(tenantID int, raws []RawInstance) {
	mu.Lock()
	defer mu.Unlock()
	// 保留本地备注与开机计时
	oldNotes := map[string]string{}
	oldRunning := map[string]*string{}
	for _, i := range data.Instances {
		if i.TenantID == tenantID {
			if i.Note != "" {
				oldNotes[i.OciID] = i.Note
			}
			oldRunning[i.OciID] = i.RunningSince
		}
	}
	instances := data.Instances[:0]
	for _, i := range data.Instances {
		if i.TenantID != tenantID {
			instances = append(instances, i)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, r := range raws {
		display := r.DisplayName
		if display == "" {
			display = "(未命名)"
		}
		var runningSince *string
		if r.LifecycleState == "RUNNING" {
			s := r.TimeCreated
			if s == "" {
				s = now
			}
			if old, ok := oldRunning[r.ID]; ok && old != nil && *old != "" {
				s = *old
			}
			runningSince = &s
		}
		privateIP, publicIP, ipv6 := first(r.PrivateIPs), first(r.PublicIPs), first(r.IPv6s)
		instances = append(instances, Instance{
			ID:                data.NextInstanceID,
			TenantID:          tenantID,
			OciID:             r.ID,
			DisplayName:       display,
			LifecycleState:    r.LifecycleState,
			Shape:             r.Shape,
			Region:            r.Region,
			AvailabilityDomain: r.AvailabilityDomain,
			CompartmentID:     r.CompartmentID,
			CreatedAt:         r.TimeCreated,
			RunningSince:      runningSince,
			PrivateIP:         privateIP,
			PublicIP:          publicIP,
			IPv6:              ipv6,
			OcpuCount:         r.Ocpus,
			MemoryInGBs:       r.MemoryInGBs,
			Arch:              r.Arch,
			BootVolumeID:      r.BootVolumeID,
			BootVolumeSize:    r.BootVolumeSize,
			VpusPerGB:         r.VpusPerGB,
			Note:              oldNotes[r.ID],
		})
		data.NextInstanceID++
	}
	data.Instances = instances
	save()
}

func first(list []string) string {
	if len(list) > 0 {
		return list[0]
	}
	return ""
}

// UpdateInstanceFields 更新单个实例的本地字段
func UpdateInstanceFields(id int, patch func(*Instance)) *Instance {
	mu.Lock()
	defer mu.Unlock()
	for i := range data.Instances {
		if data.Instances[i].ID == id {
			patch(&data.Instances[i])
			out := data.Instances[i]
			save()
			return &out
		}
	}
	return nil
}

func DeleteInstance(id int) {
	mu.Lock()
	defer mu.Unlock()
	instances := data.Instances[:0]
	for _, i := range data.Instances {
		if i.ID != id {
			instances = append(instances, i)
		}
	}
	data.Instances = instances
	save()
}

// ---- 费用 ----

// SaveDailyCostInput 单日费用入参
type SaveDailyCostInput struct {
	Date     string
	Compute  float64
	Storage  float64
	Network  float64
	Other    float64
	Total    float64
	Currency string
}

func SaveDailyCosts(tenantID int, daily []SaveDailyCostInput) {
	mu.Lock()
	defer mu.Unlock()
	key := fmt.Sprintf("%d", tenantID)
	if data.Costs[key] == nil {
		data.Costs[key] = map[string]DailyCost{}
	}
	for _, d := range daily {
		if d.Date == "" {
			continue
		}
		cur := d.Currency
		if cur == "" {
			cur = "USD"
		}
		data.Costs[key][d.Date] = DailyCost{
			Compute:   d.Compute,
			Storage:   d.Storage,
			Network:   d.Network,
			Other:     d.Other,
			Total:     d.Total,
			Currency:  cur,
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}
	save()
}

func HasCostData(tenantID int) bool {
	mu.Lock()
	defer mu.Unlock()
	m := data.Costs[fmt.Sprintf("%d", tenantID)]
	return len(m) > 0
}

// TenantDayCost 某天某租户的费用
type TenantDayCost struct {
	ID       int     `json:"id"`
	Name     string  `json:"name"`
	Compute  float64 `json:"compute"`
	Storage  float64 `json:"storage"`
	Network  float64 `json:"network"`
	Other    float64 `json:"other"`
	Total    float64 `json:"total"`
	Currency string  `json:"currency"`
}

// DayCost 跨租户汇总的一天
type DayCost struct {
	Date     string          `json:"date"`
	Compute  float64         `json:"compute"`
	Storage  float64         `json:"storage"`
	Network  float64         `json:"network"`
	Other    float64         `json:"other"`
	Total    float64         `json:"total"`
	Currency string          `json:"currency"`
	Tenants  []TenantDayCost `json:"tenants"`
}

type CostSummary struct {
	Total   float64 `json:"total"`
	Compute float64 `json:"compute"`
	Storage float64 `json:"storage"`
	Network float64 `json:"network"`
	Other   float64 `json:"other"`
}

type DailyCostsResult struct {
	Days    []DayCost    `json:"days"`
	Summary CostSummary  `json:"summary"`
}

// GetDailyCosts 读取日期范围内（含）的按天费用：跨租户汇总 + 每天的租户明细，日期倒序
func GetDailyCosts(startDate, endDate string) DailyCostsResult {
	mu.Lock()
	defer mu.Unlock()
	days := map[string]*DayCost{}
	for _, t := range data.Tenants {
		for date, v := range data.Costs[fmt.Sprintf("%d", t.ID)] {
			if date < startDate || date > endDate {
				continue
			}
			d, ok := days[date]
			if !ok {
				d = &DayCost{Date: date, Currency: orDefaultStr(v.Currency, "USD")}
				days[date] = d
			}
			cur := orDefaultStr(v.Currency, "USD")
			if cur != "" {
				d.Currency = cur
			}
			d.Compute += v.Compute
			d.Storage += v.Storage
			d.Network += v.Network
			d.Other += v.Other
			d.Total += v.Total
			name := t.CustomName
			if name == "" {
				name = t.Name
			}
			d.Tenants = append(d.Tenants, TenantDayCost{
				ID: t.ID, Name: name,
				Compute: v.Compute, Storage: v.Storage, Network: v.Network,
				Other: v.Other, Total: v.Total, Currency: cur,
			})
		}
	}
	keys := make([]string, 0, len(days))
	for k := range days {
		keys = append(keys, k)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	list := make([]DayCost, 0, len(keys))
	var summary CostSummary
	for _, k := range keys {
		d := days[k]
		d.Compute = round4(d.Compute)
		d.Storage = round4(d.Storage)
		d.Network = round4(d.Network)
		d.Other = round4(d.Other)
		d.Total = round4(d.Total)
		for i := range d.Tenants {
			tt := &d.Tenants[i]
			tt.Compute = round4(tt.Compute)
			tt.Storage = round4(tt.Storage)
			tt.Network = round4(tt.Network)
			tt.Other = round4(tt.Other)
			tt.Total = round4(tt.Total)
		}
		list = append(list, *d)
		summary.Total += d.Total
		summary.Compute += d.Compute
		summary.Storage += d.Storage
		summary.Network += d.Network
		summary.Other += d.Other
	}
	summary.Total = round4(summary.Total)
	summary.Compute = round4(summary.Compute)
	summary.Storage = round4(summary.Storage)
	summary.Network = round4(summary.Network)
	summary.Other = round4(summary.Other)
	return DailyCostsResult{Days: list, Summary: summary}
}

func orDefaultStr(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func orStr(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func round4(n float64) float64 {
	return math.Round(n*10000) / 10000
}

