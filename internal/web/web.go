// Package web 提供 HTTP 路由与页面渲染（逻辑对齐 Node 版 server.js + src/routes/*）
package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"oci-panel/internal/briefing"
	"oci-panel/internal/cryptoutil"
	"oci-panel/internal/ociutil"
	"oci-panel/internal/push"
	"oci-panel/internal/session"
	"oci-panel/internal/store"
)

//go:embed templates/*.html static/style.css
var files embed.FS

var tmpl = template.Must(template.ParseFS(files, "templates/*.html"))

var staticFS, _ = fs.Sub(files, "static")

// REGIONS 导入页可选区域（对齐 Node 版 import.js）
var REGIONS = []string{
	"ap-seoul-1", "ap-chuncheon-1", "ap-tokyo-1", "ap-osaka-1",
	"ap-singapore-1", "ap-mumbai-1", "ap-hyderabad-1", "ap-jakarta-1",
	"ap-melbourne-1", "ap-sydney-1",
	"us-ashburn-1", "us-phoenix-1", "us-sanjose-1", "ca-toronto-1",
	"sa-saopaulo-1", "sa-santiago-1", "sa-vinhedo-1", "mx-queretaro-1",
	"uk-london-1", "uk-cardiff-1",
	"eu-frankfurt-1", "eu-amsterdam-1", "eu-marseille-1", "eu-milan-1",
	"eu-zurich-1", "eu-madrid-1", "eu-stockholm-1",
	"me-jeddah-1", "me-dubai-1", "il-jerusalem-1",
	"af-johannesburg-1", "za-johannesburg-1",
}

const codeHintText = "验证码将推送至已绑定设备，有效期 5 分钟。"

// New 构造带全部路由与中间件的 Handler
func New() http.Handler {
	mux := http.NewServeMux()

	// 静态资源
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// 初始化 / 认证
	mux.HandleFunc("GET /setup", handleSetupPage)
	mux.HandleFunc("POST /setup", handleSetupSubmit)
	mux.HandleFunc("GET /login", handleLoginPage)
	mux.HandleFunc("POST /login/send-code", handleSendCode)
	mux.HandleFunc("POST /login", handleLoginSubmit)
	mux.HandleFunc("POST /logout", handleLogout)

	// 首页
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/tenants", http.StatusFound)
	})

	// 导入
	mux.HandleFunc("GET /import", handleImportPage)
	mux.HandleFunc("POST /import", handleImportSubmit)

	// 租户
	mux.HandleFunc("GET /tenants", handleTenantsPage)
	mux.HandleFunc("POST /tenants/{id}/delete", handleTenantDelete)
	mux.HandleFunc("POST /tenants/{id}/edit", handleTenantEdit)
	mux.HandleFunc("GET /tenants/{id}/test", handleTenantTest)
	mux.HandleFunc("POST /tenants/{id}/sync", handleTenantSync)

	// 实例
	mux.HandleFunc("GET /instances", handleInstancesPage)
	mux.HandleFunc("POST /instances/{id}/stop", handleInstanceStop)
	mux.HandleFunc("POST /instances/{id}/start", handleInstanceStart)
	mux.HandleFunc("POST /instances/{id}/note", handleInstanceNote)
	mux.HandleFunc("POST /instances/{id}/rename", handleInstanceRename)
	mux.HandleFunc("POST /instances/{id}/shape", handleInstanceShape)
	mux.HandleFunc("POST /instances/{id}/vpu", handleInstanceVpu)
	mux.HandleFunc("POST /instances/{id}/changeip", handleInstanceChangeIP)
	mux.HandleFunc("POST /instances/{id}/enableip6", handleInstanceEnableIP6)
	mux.HandleFunc("POST /instances/{id}/changeip6", handleInstanceChangeIP6)

	// 安全规则
	mux.HandleFunc("GET /security-rules", handleSecurityRulesPage)
	mux.HandleFunc("GET /api/security-rules", handleSecurityRulesList)
	mux.HandleFunc("POST /api/security-rules/add", handleSecurityRuleAdd)
	mux.HandleFunc("POST /api/security-rules/delete", handleSecurityRuleDelete)
	mux.HandleFunc("POST /api/security-rules/update", handleSecurityRuleUpdate)
	mux.HandleFunc("GET /api/tenants/{tenantId}/regions", handleTenantRegions)

	// 费用
	mux.HandleFunc("GET /costs", handleCostsPage)
	mux.HandleFunc("GET /api/costs/daily", handleCostsDaily)
	mux.HandleFunc("POST /api/costs/sync", handleCostsSync)
	mux.HandleFunc("GET /api/costs/details", handleCostsDetails)

	// 流量
	mux.HandleFunc("GET /api/tenants/{id}/traffic", handleTenantTraffic)
	mux.HandleFunc("POST /api/tenants/{id}/traffic-check", handleTenantTrafficCheck)
	mux.HandleFunc("POST /tenants/{id}/traffic-alert", handleTenantTrafficAlert)

	// 设置
	mux.HandleFunc("GET /settings", handleSettingsPage)
	mux.HandleFunc("POST /settings/password", handleSettingsPassword)
	mux.HandleFunc("POST /settings/channel", handleSettingsChannel)
	mux.HandleFunc("POST /settings/channel/test", handleSettingsChannelTest)
	mux.HandleFunc("POST /settings/notify", handleSettingsNotify)
	mux.HandleFunc("POST /settings/2fa", handleSettings2FA)
	mux.HandleFunc("POST /settings/notify/test", handleSettingsNotifyTest)
	mux.HandleFunc("GET /settings/export", handleSettingsExport)
	mux.HandleFunc("POST /settings/import", handleSettingsImport)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	return authMiddleware(setupMiddleware(mux))
}

// ============================================================
// 中间件
// ============================================================

type ctxKey int

const usernameKey ctxKey = 1

// 首次使用（无用户）：除 /setup 和静态资源外全部跳转初始化页
func setupMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !store.HasUser() && !strings.HasPrefix(r.URL.Path, "/setup") && !strings.HasPrefix(r.URL.Path, "/static") {
			http.Redirect(w, r, "/setup", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// 登录校验：/login /setup /static 之外需登录
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasPrefix(path, "/login") || strings.HasPrefix(path, "/setup") || strings.HasPrefix(path, "/static") {
			next.ServeHTTP(w, r)
			return
		}
		username, _, ok := session.Current(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		ctx := context.WithValue(r.Context(), usernameKey, username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func currentUsername(r *http.Request) string {
	if v, ok := r.Context().Value(usernameKey).(string); ok {
		return v
	}
	return ""
}

// ============================================================
// 视图模型
// ============================================================

// page 所有页面共用模板数据（多余字段无害）
type page struct {
	Title, Active, Username string
	Error, Success          string
	// 登录/初始化
	SuccessMsg, FormUsername, FormPassword, SubtitleText, CodePlaceholder, CodeHintText string
	TwoFaEnabled                                                                        bool
	// 列表页
	Tenants    []TenantView
	Instances  []InstanceView
	InstRegions []string
	// 导入页
	Regions   []string
	FormData  *importFormData
	// 安全规则页
	SelectedTenantID int
	SelectedRegion    string
	// 设置页
	Settings store.Settings
}

type importFormData struct {
	Name        string
	TenancyOcid string
	UserOcid    string
	Fingerprint string
	Region      string
	PrivateKey  string
}

// TenantView 租户列表行
type TenantView struct {
	ID                  int
	Name                string
	TenancyOcid         string
	CustomName          string
	DisplayName         string
	Cost                string
	Days                string
	AccountCreatedAt    string
	MainRegion          string
	MultiRegion         bool
	RegionCount         int
	RegionCountStr      string
	AccountType         string
	InstanceCount       string
	TrafficEnabled      bool
	TrafficThreshold    float64
	TrafficAutoshutdown bool
	UsedStr             string
	ThrStr              string
	UsedColor           string
	CreatedAt           string
	SyncStatus          string
	SyncError           string
	AccountState        string
}

// InstanceView 实例列表行
type InstanceView struct {
	ID                int
	TenantID          int
	TenantName        string
	TenantCustomName  string
	Region            string
	DisplayName       string
	Shape             string
	LifecycleState    string
	Arch              string
	PublicIP          string
	IPv6              string
	IPv6Short         string
	Note              string
	CpuStr            string
	MemStr            string
	DiskStr           string
	VpuStr            string
	OcpuAttr          string
	MemAttr           string
	VpuAttr           string
	UptimeStr         string
	CreatedDateStr    string
}

func render(w http.ResponseWriter, name string, data *page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "模板渲染失败: "+err.Error(), http.StatusInternalServerError)
	}
}

func jsonOut(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func errOut(w http.ResponseWriter, msg string) {
	jsonOut(w, map[string]any{"ok": false, "error": msg})
}

func okOut(w http.ResponseWriter, extra map[string]any) {
	m := map[string]any{"ok": true}
	for k, v := range extra {
		m[k] = v
	}
	jsonOut(w, m)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}

func form(r *http.Request) map[string]string {
	_ = r.ParseForm()
	m := map[string]string{}
	for k, v := range r.PostForm {
		if len(v) > 0 {
			m[k] = v[0]
		}
	}
	for k, v := range r.URL.Query() {
		if _, ok := m[k]; !ok && len(v) > 0 {
			m[k] = v[0]
		}
	}
	return m
}

func pathID(r *http.Request) (int, error) {
	return strconv.Atoi(r.PathValue("id"))
}

func trimF(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%g", f)
}

// ============================================================
// 初始化 / 认证
// ============================================================

func handleSetupPage(w http.ResponseWriter, r *http.Request) {
	if store.HasUser() {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	render(w, "setup.html", &page{Title: "初始化"})
}

var usernameRe = regexp.MustCompile(`^[\w.\-]{2,32}$`)

func handleSetupSubmit(w http.ResponseWriter, r *http.Request) {
	if store.HasUser() {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	f := form(r)
	username := strings.TrimSpace(f["username"])
	password := f["password"]
	confirm := f["confirm_password"]

	fail := func(msg string) {
		render(w, "setup.html", &page{Title: "初始化", Error: msg})
	}
	if !usernameRe.MatchString(username) {
		fail("用户名格式错误（2~32 位，字母 / 数字 / . _ -）")
		return
	}
	if len(password) < 6 {
		fail("密码至少 6 位")
		return
	}
	if password != confirm {
		fail("两次输入的密码不一致")
		return
	}
	hash, err := cryptoutil.HashPassword(password)
	if err != nil {
		fail("密码加密失败: " + err.Error())
		return
	}
	if !store.CreateUser(username, hash) {
		fail("用户名已存在")
		return
	}
	u := store.FindUser(username)
	session.Login(w, username, u.ID)
	http.Redirect(w, r, "/tenants", http.StatusFound)
}

func loginView(firstTwoFA bool, subtitle string) *page {
	p := &page{
		Title:          "登录",
		CodeHintText:   codeHintText,
		TwoFaEnabled:   firstTwoFA,
		SubtitleText:   subtitle,
	}
	if firstTwoFA {
		p.CodePlaceholder = "请输入验证码"
		p.SubtitleText = "请输入账号、密码并完成验证码验证"
	} else {
		p.CodePlaceholder = "请输入收到的验证码"
		p.SubtitleText = "请输入账号和密码登录"
	}
	return p
}

func anyUser2FA() bool {
	for _, u := range store.ListUsers() {
		if store.GetUserSettings(u.Username).TwoFAEnabled {
			return true
		}
	}
	return false
}

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := session.Current(r); ok {
		http.Redirect(w, r, "/tenants", http.StatusFound)
		return
	}
	users := store.ListUsers()
	first2fa := false
	if len(users) > 0 {
		first2fa = store.GetUserSettings(users[0].Username).TwoFAEnabled
	}
	render(w, "login.html", loginView(first2fa, ""))
}

func handleSendCode(w http.ResponseWriter, r *http.Request) {
	f := form(r)
	username := strings.TrimSpace(f["username"])
	password := f["password"]
	if username == "" || password == "" {
		errOut(w, "请填写账号和密码")
		return
	}
	ip := clientIP(r)
	if push.RateLimited("sc:"+ip+"|"+username, 5, 10*time.Minute) {
		errOut(w, "发送太频繁，请 10 分钟后再试")
		return
	}
	user := store.FindUser(username)
	if user == nil || !cryptoutil.VerifyPassword(password, user.PasswordHash) {
		errOut(w, "账号或密码错误")
		return
	}
	s := store.GetUserSettings(username)
	if !s.TwoFAEnabled {
		errOut(w, `该账号未启用二次验证，直接点击"登录"即可`)
		return
	}
	provider := push.BuildProviderFromSettings(s, s.TwoFAChannel)
	res := push.SendCode(provider, username, ip)
	if res.Ok {
		okOut(w, nil)
		return
	}
	errOut(w, res.Error)
}

func handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	f := form(r)
	username := strings.TrimSpace(f["username"])
	password := f["password"]
	code := strings.TrimSpace(f["code"])
	ip := clientIP(r)
	rlKey := "lg:" + ip + "|" + username
	if push.RateLimited(rlKey, 10, 15*time.Minute) {
		p := loginView(true, "")
		p.Error = "尝试次数过多，请 15 分钟后再试"
		render(w, "login.html", p)
		return
	}

	failLogin := func(msg, subtitle string) {
		p := loginView(anyUser2FA(), "")
		p.Error = msg
		p.FormUsername = username
		if subtitle != "" {
			p.SubtitleText = subtitle
		}
		render(w, "login.html", p)
	}

	user := store.FindUser(username)
	if user == nil || !cryptoutil.VerifyPassword(password, user.PasswordHash) {
		failLogin("用户名或密码错误", "")
		return
	}
	s := store.GetUserSettings(username)
	if s.TwoFAEnabled {
		if code == "" {
			failLogin(`请先点击"获取验证码"，再填入收到的验证码`, "请输入账号、密码并完成验证码验证")
			return
		}
		v := push.VerifyCode(username, code)
		if !v.Ok {
			failLogin(v.Error, "请输入账号、密码并完成验证码验证")
			return
		}
	}
	session.Login(w, user.Username, user.ID)
	push.RateClear(rlKey)
	http.Redirect(w, r, "/tenants", http.StatusFound)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	session.Logout(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// ============================================================
// 导入
// ============================================================

func handleImportPage(w http.ResponseWriter, r *http.Request) {
	render(w, "import.html", &page{Title: "API 导入", Active: "tenants", Username: currentUsername(r), Regions: REGIONS})
}

func handleImportSubmit(w http.ResponseWriter, r *http.Request) {
	f := form(r)
	fd := &importFormData{
		Name: f["name"], TenancyOcid: f["tenancy_ocid"], UserOcid: f["user_ocid"],
		Fingerprint: f["fingerprint"], Region: f["region"], PrivateKey: f["private_key"],
	}
	fail := func(msg string) {
		render(w, "import.html", &page{
			Title: "API 导入", Active: "tenants", Username: currentUsername(r),
			Regions: REGIONS, Error: msg, FormData: fd,
		})
	}
	if fd.Name == "" || fd.TenancyOcid == "" || fd.UserOcid == "" || fd.Fingerprint == "" || fd.Region == "" || fd.PrivateKey == "" {
		fail("所有字段均为必填")
		return
	}
	if !strings.HasPrefix(strings.TrimSpace(fd.TenancyOcid), "ocid1.tenancy.") {
		fail("Tenancy OCID 格式错误（应以 ocid1.tenancy. 开头）")
		return
	}
	if !strings.HasPrefix(strings.TrimSpace(fd.UserOcid), "ocid1.user.") {
		fail("User OCID 格式错误（应以 ocid1.user. 开头）")
		return
	}
	if !strings.Contains(fd.PrivateKey, "PRIVATE KEY") {
		fail("私钥格式错误（应为 PEM 格式，-----BEGIN PRIVATE KEY----- 开头）")
		return
	}
	enc, err := cryptoutil.EncryptText(strings.TrimSpace(fd.PrivateKey))
	if err != nil {
		fail("私钥加密失败: " + err.Error())
		return
	}
	store.AddTenant(store.Tenant{
		Name:          strings.TrimSpace(fd.Name),
		TenancyOcid:   strings.TrimSpace(fd.TenancyOcid),
		UserOcid:      strings.TrimSpace(fd.UserOcid),
		Fingerprint:   strings.TrimSpace(fd.Fingerprint),
		Region:        fd.Region,
		PrivateKeyEnc: enc,
	})
	http.Redirect(w, r, "/tenants", http.StatusFound)
}

// ============================================================
// 租户
// ============================================================

func buildTenantViews() []TenantView {
	tenants := store.ListTenants()
	out := make([]TenantView, 0, len(tenants))
	now := time.Now()
	for _, t := range tenants {
		v := TenantView{
			ID: t.ID, Name: t.Name, TenancyOcid: t.TenancyOcid,
			CustomName: t.CustomName, Cost: t.Cost,
			AccountCreatedAt: t.AccountCreatedAt,
			MultiRegion: t.MultiRegion, RegionCount: t.RegionCount,
			AccountType: t.AccountType,
			TrafficEnabled: t.TrafficEnabled, TrafficThreshold: t.TrafficThreshold,
			TrafficAutoshutdown: t.TrafficAutoshutdown,
			CreatedAt: t.CreatedAt, SyncStatus: t.SyncStatus, SyncError: t.SyncError,
			AccountState: t.AccountState,
		}
		if v.Cost == "" {
			v.Cost = "0"
		}
		if v.AccountType == "" {
			v.AccountType = "FREE"
		}
		home := t.HomeRegion
		if home == "" {
			home = t.Region
		}
		v.MainRegion = home
		v.DisplayName = t.CustomName
		if v.DisplayName == "" {
			v.DisplayName = "DEFAULT_" + home
		}
		v.RegionCountStr = strconv.Itoa(t.RegionCount)
		v.InstanceCount = strconv.Itoa(len(store.ListInstances(t.ID)))
		// 存活天数
		v.Days = "-"
		if t.AccountCreatedAt != "" {
			if created, err := parseAnyTime(t.AccountCreatedAt); err == nil {
				if d := int(now.Sub(created).Hours() / 24); d >= 0 {
					v.Days = fmt.Sprintf("%d", d)
				}
			}
		}
		// 流量预警列
		if t.TrafficEnabled {
			used := 0.0
			if t.TrafficLastTotalGB != nil {
				used = *t.TrafficLastTotalGB
			}
			thr := t.TrafficThreshold
			if thr == 0 {
				thr = 9000
			}
			if used >= 1024 {
				v.UsedStr = fmt.Sprintf("%.2fT", used/1024)
			} else {
				v.UsedStr = fmt.Sprintf("%.2fG", used)
			}
			if thr >= 1024 {
				v.ThrStr = fmt.Sprintf("%.1fT", thr/1024)
			} else {
				v.ThrStr = fmt.Sprintf("%gG", thr)
			}
			switch {
			case used > thr:
				v.UsedColor = "#d32f2f"
			case used > thr*0.9:
				v.UsedColor = "#f57c00"
			default:
				v.UsedColor = "#2e7d32"
			}
		}
		out = append(out, v)
	}
	return out
}

func parseAnyTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05.000Z", "2006-01-02T15:04:05.000Z07:00", "2006/1/2 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("无法解析时间: %s", s)
}

func handleTenantsPage(w http.ResponseWriter, r *http.Request) {
	render(w, "tenants.html", &page{
		Title: "租户管理", Active: "tenants", Username: currentUsername(r),
		Tenants: buildTenantViews(),
	})
}

func handleTenantDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := pathID(r)
	store.DeleteTenant(id)
	http.Redirect(w, r, "/tenants", http.StatusFound)
}

func handleTenantEdit(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		errOut(w, "租户 ID 无效")
		return
	}
	f := form(r)
	customName := strings.TrimSpace(f["custom_name"])
	cost := strings.TrimSpace(f["cost"])
	accountType := f["account_type"]
	if accountType == "" {
		accountType = "FREE"
	}
	t := store.UpdateTenantFields(id, store.TenantFields{
		CustomName:  &customName,
		Cost:        &cost,
		AccountType: &accountType,
	})
	if t == nil {
		errOut(w, "租户不存在")
		return
	}
	okOut(w, map[string]any{"tenant": t})
}

func handleTenantTest(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		errOut(w, "租户 ID 无效")
		return
	}
	t := store.GetTenant(id)
	if t == nil {
		jsonOut(w, map[string]any{"ok": false, "message": "租户不存在"})
		return
	}
	c, err := ociutil.CredsFromTenant(t)
	if err != nil {
		jsonOut(w, map[string]any{"ok": false, "message": err.Error()})
		return
	}
	ok, message := ociutil.TestConnection(c)
	jsonOut(w, map[string]any{"ok": ok, "message": message})
}

func handleTenantSync(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		errOut(w, "租户 ID 无效")
		return
	}
	t := store.GetTenant(id)
	if t == nil {
		errOut(w, "租户不存在")
		return
	}
	c, err := ociutil.CredsFromTenant(t)
	if err != nil {
		errOut(w, err.Error())
		return
	}
	// 同步前先测试连接
	ok, message := ociutil.TestConnection(c)
	if !ok {
		store.UpdateTenantSyncInfo(id, store.SyncInfo{Status: "error", Error: message})
		errOut(w, "认证失败："+message)
		return
	}
	res, err := ociutil.ListAllInstances(c)
	if err != nil {
		store.UpdateTenantSyncInfo(id, store.SyncInfo{Status: "error", Error: err.Error()})
		errOut(w, err.Error())
		return
	}
	store.ReplaceTenantInstances(id, res.Raws)
	info := ociutil.GetTenancyInfo(c)
	homeRegion := res.HomeRegion
	if homeRegion == "" {
		homeRegion = t.Region
	}
	store.UpdateTenantSyncInfo(id, store.SyncInfo{
		Status:           "ok",
		HomeRegion:       homeRegion,
		MultiRegion:      res.RegionCount > 1,
		RegionCount:      res.RegionCount,
		InstanceCount:    len(res.Raws),
		AccountCreatedAt: info.AccountCreatedAt,
		AccountState:     info.AccountState,
	})
	errs := res.Errors
	if errs == nil {
		errs = []string{}
	}
	okOut(w, map[string]any{"instanceCount": len(res.Raws), "errors": errs})
}

// ============================================================
// 实例
// ============================================================

func buildInstanceViews() ([]InstanceView, []TenantView, []string) {
	tenants := store.ListTenants()
	tenantName := map[int]string{}
	tenantCustom := map[int]string{}
	tenantViews := make([]TenantView, 0, len(tenants))
	for _, t := range tenants {
		name := t.CustomName
		if name == "" {
			name = t.Name
		}
		tenantName[t.ID] = t.Name
		tenantCustom[t.ID] = name
		tenantViews = append(tenantViews, TenantView{ID: t.ID, Name: t.Name})
	}
	instances := store.ListInstances(0)
	regionSet := map[string]bool{}
	out := make([]InstanceView, 0, len(instances))
	now := time.Now()
	for _, i := range instances {
		v := InstanceView{
			ID: i.ID, TenantID: i.TenantID,
			TenantName:       tenantName[i.TenantID],
			TenantCustomName: tenantCustom[i.TenantID],
			Region:           i.Region, DisplayName: i.DisplayName, Shape: i.Shape,
			LifecycleState: i.LifecycleState, Arch: i.Arch,
			PublicIP: i.PublicIP, IPv6: i.IPv6, Note: i.Note,
		}
		if v.TenantName == "" {
			v.TenantName = "-"
		}
		if v.TenantCustomName == "" {
			v.TenantCustomName = "-"
		}
		if i.Region != "" {
			regionSet[i.Region] = true
		}
		v.CpuStr, v.OcpuAttr = "-", ""
		if i.OcpuCount != nil {
			v.CpuStr = trimF(*i.OcpuCount) + "C"
			v.OcpuAttr = trimF(*i.OcpuCount)
		}
		v.MemStr, v.MemAttr = "-", ""
		if i.MemoryInGBs != nil {
			v.MemStr = trimF(*i.MemoryInGBs) + "G"
			v.MemAttr = trimF(*i.MemoryInGBs)
		}
		v.DiskStr = "-"
		if i.BootVolumeSize != nil {
			v.DiskStr = trimF(*i.BootVolumeSize) + "G"
		}
		v.VpuStr, v.VpuAttr = "-", ""
		if i.VpusPerGB != nil {
			v.VpuStr = trimF(*i.VpusPerGB)
			v.VpuAttr = trimF(*i.VpusPerGB)
		}
		if len(i.IPv6) > 14 {
			v.IPv6Short = i.IPv6[:14]
		} else {
			v.IPv6Short = i.IPv6
		}
		v.UptimeStr = "-"
		if i.LifecycleState == "RUNNING" && i.RunningSince != nil {
			if rs, err := time.Parse(time.RFC3339, *i.RunningSince); err == nil {
				if d := int(now.Sub(rs).Hours() / 24); d >= 0 {
					v.UptimeStr = fmt.Sprintf("%d天", d)
				}
			}
		}
		if len(i.CreatedAt) >= 10 {
			v.CreatedDateStr = i.CreatedAt[:10]
		}
		out = append(out, v)
	}
	regions := make([]string, 0, len(regionSet))
	for rg := range regionSet {
		regions = append(regions, rg)
	}
	sort.Strings(regions)
	return out, tenantViews, regions
}

func handleInstancesPage(w http.ResponseWriter, r *http.Request) {
	instances, tenants, regions := buildInstanceViews()
	render(w, "instances.html", &page{
		Title: "实例列表", Active: "instances", Username: currentUsername(r),
		Instances: instances, Tenants: tenants, InstRegions: regions,
	})
}

type instanceCtx struct {
	creds    ociutil.Creds
	instance store.Instance
}

func loadInstanceCtx(r *http.Request) (*instanceCtx, string) {
	id, err := pathID(r)
	if err != nil {
		return nil, "实例 ID 无效"
	}
	inst := store.GetInstance(id)
	if inst == nil {
		return nil, "实例不存在"
	}
	t := store.GetTenant(inst.TenantID)
	if t == nil {
		return nil, "所属租户不存在"
	}
	creds, err := ociutil.CredsFromTenant(t)
	if err != nil {
		return nil, err.Error()
	}
	return &instanceCtx{creds: creds.WithRegion(inst.Region), instance: *inst}, ""
}

func handleInstanceStop(w http.ResponseWriter, r *http.Request) {
	ctx, e := loadInstanceCtx(r)
	if e != "" {
		errOut(w, e)
		return
	}
	res := ociutil.StopInstance(ctx.creds, ctx.instance.OciID)
	if res.Ok {
		store.UpdateInstanceFields(ctx.instance.ID, func(i *store.Instance) {
			i.LifecycleState = "STOPPING"
			i.RunningSince = nil
		})
	}
	jsonOut(w, res)
}

func handleInstanceStart(w http.ResponseWriter, r *http.Request) {
	ctx, e := loadInstanceCtx(r)
	if e != "" {
		errOut(w, e)
		return
	}
	res := ociutil.StartInstance(ctx.creds, ctx.instance.OciID)
	if res.Ok {
		now := time.Now().UTC().Format(time.RFC3339)
		store.UpdateInstanceFields(ctx.instance.ID, func(i *store.Instance) {
			i.LifecycleState = "STARTING"
			i.RunningSince = &now
		})
	}
	jsonOut(w, res)
}

func handleInstanceNote(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		errOut(w, "实例 ID 无效")
		return
	}
	f := form(r)
	note := strings.TrimSpace(f["note"])
	inst := store.UpdateInstanceFields(id, func(i *store.Instance) { i.Note = note })
	if inst == nil {
		errOut(w, "实例不存在")
		return
	}
	okOut(w, map[string]any{"note": inst.Note})
}

func handleInstanceRename(w http.ResponseWriter, r *http.Request) {
	ctx, e := loadInstanceCtx(r)
	if e != "" {
		errOut(w, e)
		return
	}
	name := strings.TrimSpace(form(r)["display_name"])
	if name == "" {
		errOut(w, "名称不能为空")
		return
	}
	res := ociutil.UpdateInstanceName(ctx.creds, ctx.instance.OciID, name)
	if res.Ok {
		store.UpdateInstanceFields(ctx.instance.ID, func(i *store.Instance) { i.DisplayName = name })
	}
	jsonOut(w, res)
}

func handleInstanceShape(w http.ResponseWriter, r *http.Request) {
	ctx, e := loadInstanceCtx(r)
	if e != "" {
		errOut(w, e)
		return
	}
	f := form(r)
	ocpus, err1 := strconv.ParseFloat(f["ocpus"], 64)
	memory, err2 := strconv.ParseFloat(f["memory"], 64)
	if err1 != nil || err2 != nil || ocpus == 0 || memory == 0 {
		errOut(w, "CPU 和内存均不能为空")
		return
	}
	if !strings.Contains(strings.ToLower(ctx.instance.Shape), "flex") {
		errOut(w, fmt.Sprintf("形状 %s 不支持在线调整配置（仅 Flex 形状支持）", ctx.instance.Shape))
		return
	}
	if ctx.instance.LifecycleState == "RUNNING" || ctx.instance.LifecycleState == "STARTING" {
		errOut(w, "实例运行中无法修改配置，请先停止实例")
		return
	}
	res := ociutil.UpdateInstanceShape(ctx.creds, ctx.instance.OciID, ocpus, memory)
	if res.Ok {
		store.UpdateInstanceFields(ctx.instance.ID, func(i *store.Instance) {
			i.OcpuCount = &ocpus
			i.MemoryInGBs = &memory
		})
	}
	jsonOut(w, res)
}

func handleInstanceVpu(w http.ResponseWriter, r *http.Request) {
	ctx, e := loadInstanceCtx(r)
	if e != "" {
		errOut(w, e)
		return
	}
	vpu, err := strconv.ParseFloat(form(r)["vpu"], 64)
	if err != nil || vpu != float64(int64(vpu)) || vpu < 10 || vpu > 120 {
		errOut(w, "VPU 必须是 10-120 之间的整数")
		return
	}
	if int64(vpu)%10 != 0 {
		errOut(w, "VPU 必须是 10 的倍数（10/20/.../120）")
		return
	}
	if ctx.instance.BootVolumeID == "" {
		errOut(w, "未找到引导卷（请先重新同步租户）")
		return
	}
	res := ociutil.UpdateBootVolumeVpu(ctx.creds, ctx.instance.BootVolumeID, vpu)
	if res.Ok {
		store.UpdateInstanceFields(ctx.instance.ID, func(i *store.Instance) { i.VpusPerGB = &vpu })
	}
	jsonOut(w, res)
}

func handleInstanceChangeIP(w http.ResponseWriter, r *http.Request) {
	ctx, e := loadInstanceCtx(r)
	if e != "" {
		errOut(w, e)
		return
	}
	res := ociutil.ChangePublicIp(ctx.creds, ctx.instance.OciID, ctx.instance.CompartmentID)
	if res.Ok {
		newIP := res.NewIp
		store.UpdateInstanceFields(ctx.instance.ID, func(i *store.Instance) { i.PublicIP = newIP })
	}
	jsonOut(w, res)
}

func handleInstanceEnableIP6(w http.ResponseWriter, r *http.Request) {
	ctx, e := loadInstanceCtx(r)
	if e != "" {
		errOut(w, e)
		return
	}
	if ctx.instance.IPv6 != "" {
		errOut(w, `该实例已启用 IPv6，如需更换地址请用「切换 IPv6」`)
		return
	}
	res := ociutil.EnableInstanceIpv6(ctx.creds, ctx.instance.OciID, ctx.instance.CompartmentID, false)
	if res.Ok {
		ipv6 := res.Ipv6
		store.UpdateInstanceFields(ctx.instance.ID, func(i *store.Instance) { i.IPv6 = ipv6 })
	}
	jsonOut(w, res)
}

func handleInstanceChangeIP6(w http.ResponseWriter, r *http.Request) {
	ctx, e := loadInstanceCtx(r)
	if e != "" {
		errOut(w, e)
		return
	}
	res := ociutil.ChangeInstanceIpv6(ctx.creds, ctx.instance.OciID, ctx.instance.CompartmentID)
	if res.Ok {
		ipv6 := res.Ipv6
		store.UpdateInstanceFields(ctx.instance.ID, func(i *store.Instance) { i.IPv6 = ipv6 })
	}
	jsonOut(w, res)
}

// ============================================================
// 安全规则
// ============================================================

func handleSecurityRulesPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tenants := store.ListTenants()
	selected := 0
	if v := q.Get("tenantId"); v != "" {
		if id, err := strconv.Atoi(v); err == nil {
			selected = id
		}
	}
	if selected == 0 && len(tenants) > 0 {
		selected = tenants[0].ID
	}
	selectedRegion := ""
	if t := store.GetTenant(selected); t != nil {
		selectedRegion = q.Get("region")
		if selectedRegion == "" {
			selectedRegion = t.HomeRegion
		}
		if selectedRegion == "" {
			selectedRegion = t.Region
		}
	}
	views := make([]TenantView, 0, len(tenants))
	for _, t := range tenants {
		views = append(views, TenantView{ID: t.ID, Name: t.Name})
	}
	render(w, "security-rules.html", &page{
		Title: "安全规则管理", Active: "security-rules", Username: currentUsername(r),
		Tenants: views, SelectedTenantID: selected, SelectedRegion: selectedRegion,
	})
}

func securityRuleCreds(r *http.Request) (ociutil.Creds, string) {
	f := form(r)
	tenantID, err := strconv.Atoi(f["tenantId"])
	if err != nil {
		return ociutil.Creds{}, "租户 ID 无效"
	}
	t := store.GetTenant(tenantID)
	if t == nil {
		return ociutil.Creds{}, "租户不存在"
	}
	c, err := ociutil.CredsFromTenant(t)
	if err != nil {
		return ociutil.Creds{}, err.Error()
	}
	if region := f["region"]; region != "" {
		c = c.WithRegion(region)
	}
	return c, ""
}

func handleSecurityRulesList(w http.ResponseWriter, r *http.Request) {
	f := form(r)
	c, e := securityRuleCreds(r)
	if e != "" {
		errOut(w, e)
		return
	}
	result := ociutil.ListSecurityRules(c, f["compartmentId"])
	if result.Ingress == nil {
		result.Ingress = []ociutil.RuleView{}
	}
	if result.Egress == nil {
		result.Egress = []ociutil.RuleView{}
	}
	if result.SecurityLists == nil {
		result.SecurityLists = []ociutil.SecurityListInfo{}
	}
	jsonOut(w, result)
}

func ruleInputFromForm(f map[string]string) ociutil.RuleInput {
	return ociutil.RuleInput{
		Direction: f["direction"], Source: f["source"], Destination: f["destination"],
		Protocol: f["protocol"], PortMin: f["portMin"], PortMax: f["portMax"],
		IcmpType: f["icmpType"], Description: f["description"], SourceType: f["sourceType"],
	}
}

func handleSecurityRuleAdd(w http.ResponseWriter, r *http.Request) {
	f := form(r)
	if f["securityListId"] == "" {
		errOut(w, "请选择 Security List")
		return
	}
	c, e := securityRuleCreds(r)
	if e != "" {
		errOut(w, e)
		return
	}
	jsonOut(w, ociutil.AddSecurityRule(c, f["securityListId"], ruleInputFromForm(f)))
}

func handleSecurityRuleDelete(w http.ResponseWriter, r *http.Request) {
	f := form(r)
	c, e := securityRuleCreds(r)
	if e != "" {
		errOut(w, e)
		return
	}
	idx, err := strconv.Atoi(f["localIndex"])
	if err != nil {
		errOut(w, "规则索引无效")
		return
	}
	jsonOut(w, ociutil.DeleteSecurityRule(c, f["securityListId"], f["direction"], idx))
}

func handleSecurityRuleUpdate(w http.ResponseWriter, r *http.Request) {
	f := form(r)
	c, e := securityRuleCreds(r)
	if e != "" {
		errOut(w, e)
		return
	}
	idx, err := strconv.Atoi(f["localIndex"])
	if err != nil {
		errOut(w, "规则索引无效")
		return
	}
	jsonOut(w, ociutil.UpdateSecurityRule(c, f["securityListId"], f["direction"], idx, ruleInputFromForm(f)))
}

func handleTenantRegions(w http.ResponseWriter, r *http.Request) {
	tenantID, err := strconv.Atoi(r.PathValue("tenantId"))
	if err != nil {
		errOut(w, "租户 ID 无效")
		return
	}
	t := store.GetTenant(tenantID)
	if t == nil {
		errOut(w, "租户不存在")
		return
	}
	c, err := ociutil.CredsFromTenant(t)
	if err != nil {
		errOut(w, err.Error())
		return
	}
	regions, err := ociutil.ListSubscribedRegions(c)
	if err != nil {
		errOut(w, ociutil.ErrInfo(err))
		return
	}
	names := make([]string, 0, len(regions))
	for _, rg := range regions {
		name := rg.Name
		if name == "" {
			name = rg.RegionKey
		}
		names = append(names, name)
	}
	okOut(w, map[string]any{"regions": names})
}

// ============================================================
// 费用
// ============================================================

func handleCostsPage(w http.ResponseWriter, r *http.Request) {
	render(w, "costs.html", &page{
		Title: "费用统计", Active: "costs", Username: currentUsername(r),
	})
}

var dateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

func handleCostsDaily(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	startDate, endDate := q.Get("startDate"), q.Get("endDate")
	if !dateRe.MatchString(startDate) || !dateRe.MatchString(endDate) {
		errOut(w, "日期格式错误")
		return
	}
	if startDate > endDate {
		errOut(w, "起始日期不能晚于结束日期")
		return
	}
	result := store.GetDailyCosts(startDate, endDate)
	out := map[string]any{
		"ok": true, "days": result.Days, "summary": result.Summary,
	}
	if len(result.Days) > 0 {
		out["currency"] = result.Days[0].Currency
	} else {
		out["currency"] = "USD"
	}
	jsonOut(w, out)
}

func handleCostsSync(w http.ResponseWriter, r *http.Request) {
	results := ociutil.SyncAllTenantsCosts()
	var errs []string
	for _, t := range results {
		if t.Error != "" {
			errs = append(errs, fmt.Sprintf("%s: %s", t.Name, t.Error))
		}
	}
	if results == nil {
		results = []ociutil.TenantCostSyncResult{}
	}
	jsonOut(w, map[string]any{
		"ok": len(errs) == 0, "tenants": results,
		"error": strings.Join(errs, "；"),
	})
}

func handleCostsDetails(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tenantID, err := strconv.Atoi(q.Get("tenantId"))
	if err != nil {
		errOut(w, "租户 ID 无效")
		return
	}
	startDate, endDate := q.Get("startDate"), q.Get("endDate")
	t := store.GetTenant(tenantID)
	if t == nil {
		errOut(w, "租户不存在")
		return
	}
	c, err := ociutil.CredsFromTenant(t)
	if err != nil {
		errOut(w, err.Error())
		return
	}
	c.AccountCreatedAt = t.AccountCreatedAt
	items, err := ociutil.QueryCostDetails(c, startDate, endDate)
	if err != nil {
		errOut(w, ociutil.ErrInfo(err))
		return
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].ComputedAmount > items[j].ComputedAmount })
	okOut(w, map[string]any{"items": items})
}

// ============================================================
// 流量
// ============================================================

func tenantCredsByID(idStr string) (int, *store.Tenant, string) {
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return 0, nil, "租户 ID 无效"
	}
	t := store.GetTenant(id)
	if t == nil {
		return id, nil, "租户不存在"
	}
	return id, t, ""
}

func handleTenantTraffic(w http.ResponseWriter, r *http.Request) {
	id, t, e := tenantCredsByID(r.PathValue("id"))
	if e != "" {
		errOut(w, e)
		return
	}
	_ = id
	c, err := ociutil.CredsFromTenant(t)
	if err != nil {
		errOut(w, err.Error())
		return
	}
	result, err := ociutil.QueryTenantMonthTraffic(c)
	if err != nil {
		errOut(w, ociutil.ErrInfo(err))
		return
	}
	jsonOut(w, map[string]any{
		"ok": true, "egressGB": result.EgressGB, "ingressGB": result.IngressGB,
		"details": result.Details, "monthStart": result.MonthStart, "queryTime": result.QueryTime,
	})
}

func handleTenantTrafficCheck(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, _, e := tenantCredsByID(idStr)
	if e != "" {
		errOut(w, e)
		return
	}
	full := store.GetTenant(id) // 含私钥
	result := ociutil.CheckAndAlert(full)
	now := time.Now().UTC().Format(time.RFC3339)
	store.UpdateTenantFields(id, store.TenantFields{
		TrafficLastChecked: &now,
		TrafficLastTotalGB: &result.EgressGB,
		TrafficLastExceeded: &result.Exceeded,
	})
	jsonOut(w, result)
}

func handleTenantTrafficAlert(w http.ResponseWriter, r *http.Request) {
	id, _, e := tenantCredsByID(r.PathValue("id"))
	if e != "" {
		errOut(w, e)
		return
	}
	f := form(r)
	enabled := f["traffic_enabled"] == "on" || f["traffic_enabled"] == "true"
	threshold := 9000.0
	if v, err := strconv.ParseFloat(f["traffic_threshold"], 64); err == nil && v != 0 {
		threshold = v
	}
	shutdown := f["traffic_autoshutdown"] == "on" || f["traffic_autoshutdown"] == "true"
	updated := store.UpdateTenantFields(id, store.TenantFields{
		TrafficEnabled:      &enabled,
		TrafficThreshold:    &threshold,
		TrafficAutoshutdown: &shutdown,
	})
	if updated == nil {
		errOut(w, "租户不存在")
		return
	}
	okOut(w, map[string]any{"tenant": updated})
}

// ============================================================
// 设置
// ============================================================

func settingsPage(r *http.Request, errMsg, success string) *page {
	username := currentUsername(r)
	return &page{
		Title: "设置", Active: "settings", Username: username,
		Settings: store.GetUserSettings(username),
		Error:    errMsg, Success: success,
	}
}

func handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	render(w, "settings.html", settingsPage(r, "", ""))
}

func handleSettingsPassword(w http.ResponseWriter, r *http.Request) {
	f := form(r)
	username := currentUsername(r)
	user := store.FindUser(username)
	if user == nil {
		render(w, "settings.html", settingsPage(r, "用户不存在", ""))
		return
	}
	if !cryptoutil.VerifyPassword(f["current_password"], user.PasswordHash) {
		render(w, "settings.html", settingsPage(r, "当前密码错误", ""))
		return
	}
	newPassword := f["new_password"]
	if len(newPassword) < 6 {
		render(w, "settings.html", settingsPage(r, "新密码至少 6 位", ""))
		return
	}
	if newPassword != f["confirm_password"] {
		render(w, "settings.html", settingsPage(r, "两次输入的新密码不一致", ""))
		return
	}
	hash, err := cryptoutil.HashPassword(newPassword)
	if err != nil {
		render(w, "settings.html", settingsPage(r, "密码加密失败: "+err.Error(), ""))
		return
	}
	store.UpdateUserPassword(username, hash)
	render(w, "settings.html", settingsPage(r, "", "密码已修改，请重新登录"))
}

func handleSettingsChannel(w http.ResponseWriter, r *http.Request) {
	f := form(r)
	username := currentUsername(r)
	barkURL := strings.TrimSpace(f["bark_url"])
	barkKey := strings.TrimSpace(f["bark_key"])
	pushplusToken := strings.TrimSpace(f["pushplus_token"])

	var errs []string
	if barkKey != "" {
		if res := push.TestPush(push.Provider{Provider: "bark", BarkURL: barkURL, BarkKey: barkKey}); !res.Ok {
			errs = append(errs, "Bark："+res.Error)
		}
	}
	if pushplusToken != "" {
		if res := push.TestPush(push.Provider{Provider: "pushplus", Token: pushplusToken}); !res.Ok {
			errs = append(errs, "PushPlus："+res.Error)
		}
	}
	store.UpdateUserSettings(username, func(s *store.Settings) {
		s.BarkURL, s.BarkKey, s.PushplusToken = barkURL, barkKey, pushplusToken
	})
	if len(errs) > 0 {
		render(w, "settings.html", settingsPage(r, "配置已保存，但部分渠道测试失败："+strings.Join(errs, "；"), ""))
		return
	}
	render(w, "settings.html", settingsPage(r, "", "推送渠道设置已保存，测试消息已发出"))
}

func handleSettingsChannelTest(w http.ResponseWriter, r *http.Request) {
	f := form(r)
	provider := strings.TrimSpace(f["provider"])
	if provider == "" {
		provider = "bark"
	}
	barkURL := strings.TrimSpace(f["bark_url"])
	if barkURL == "" {
		barkURL = "https://api.day.app"
	}
	res := push.TestPush(push.Provider{
		Provider: provider, BarkURL: barkURL,
		BarkKey: strings.TrimSpace(f["bark_key"]), Token: strings.TrimSpace(f["pushplus_token"]),
	})
	jsonOut(w, res)
}

var timeRe = regexp.MustCompile(`^([01]?[0-9]|2[0-3]):[0-5][0-9]$`)

func handleSettingsNotify(w http.ResponseWriter, r *http.Request) {
	f := form(r)
	username := currentUsername(r)
	notifyEnabled := f["notify_enabled"] == "on"
	notifyTime := strings.TrimSpace(f["notify_time"])
	if notifyTime == "" {
		notifyTime = "09:00"
	}
	notifyChannel := strings.TrimSpace(f["notify_channel"])
	if notifyChannel == "" {
		notifyChannel = "bark"
	}
	if notifyChannel != "bark" && notifyChannel != "pushplus" {
		render(w, "settings.html", settingsPage(r, "通知任务推送渠道无效", ""))
		return
	}
	if !timeRe.MatchString(notifyTime) {
		render(w, "settings.html", settingsPage(r, "执行时间格式错误，应为 HH:MM（00:00 ~ 23:59）", ""))
		return
	}
	if notifyEnabled {
		s := store.GetUserSettings(username)
		if notifyChannel == "bark" && s.BarkKey == "" {
			render(w, "settings.html", settingsPage(r, "所选渠道未配置：请先在上方「推送渠道」填写 Bark 设备 Key 并保存", ""))
			return
		}
		if notifyChannel == "pushplus" && s.PushplusToken == "" {
			render(w, "settings.html", settingsPage(r, "所选渠道未配置：请先在上方「推送渠道」填写 PushPlus Token 并保存", ""))
			return
		}
	}
	store.UpdateUserSettings(username, func(s *store.Settings) {
		s.NotifyEnabled = notifyEnabled
		s.NotifyTime = notifyTime
		s.NotifyChannel = notifyChannel
		s.NotifyCostsDaily = f["notify_costs_daily"] == "on"
		s.NotifyAccountHealth = f["notify_account_health"] == "on"
		s.NotifyTrafficAlert = f["notify_traffic_alert"] == "on"
	})
	chName := "Bark"
	if notifyChannel == "pushplus" {
		chName = "PushPlus"
	}
	msg := "通知任务已关闭"
	if notifyEnabled {
		msg = fmt.Sprintf("通知任务已开启（每天 %s 推送到 %s）", notifyTime, chName)
	}
	render(w, "settings.html", settingsPage(r, "", msg))
}

func handleSettings2FA(w http.ResponseWriter, r *http.Request) {
	f := form(r)
	username := currentUsername(r)
	enable := f["two_fa_enabled"] == "on"
	ch := strings.TrimSpace(f["two_fa_channel"])
	if ch == "" {
		ch = "bark"
	}
	if ch != "bark" && ch != "pushplus" {
		render(w, "settings.html", settingsPage(r, "2FA 推送渠道无效", ""))
		return
	}
	settings := store.GetUserSettings(username)

	if enable {
		if ch == "bark" && settings.BarkKey == "" {
			render(w, "settings.html", settingsPage(r, "Bark 未配置，请先在「推送渠道」中填写并保存 Bark 设备 Key", ""))
			return
		}
		if ch == "pushplus" && settings.PushplusToken == "" {
			render(w, "settings.html", settingsPage(r, "PushPlus 未配置，请先在「推送渠道」中填写并保存 PushPlus Token", ""))
			return
		}
		// 渠道必须测试推送能过
		provider := push.BuildProviderFromSettings(settings, ch)
		if res := push.TestPush(provider); !res.Ok {
			store.UpdateUserSettings(username, func(s *store.Settings) {
				s.TwoFAChannel = ch
				s.TwoFAEnabled = false
			})
			render(w, "settings.html", settingsPage(r, "2FA 推送测试失败，未开启："+res.Error+"（请先确认「推送渠道」配置正常）", ""))
			return
		}
		store.UpdateUserSettings(username, func(s *store.Settings) {
			s.TwoFAEnabled = true
			s.TwoFAChannel = ch
		})
		chName := "Bark"
		if ch == "pushplus" {
			chName = "PushPlus"
		}
		render(w, "settings.html", settingsPage(r, "", fmt.Sprintf("2FA 二次验证已开启（使用 %s），下次登录需要输入验证码", chName)))
		return
	}
	prev := settings.TwoFAEnabled
	store.UpdateUserSettings(username, func(s *store.Settings) {
		s.TwoFAEnabled = false
		s.TwoFAChannel = ch
	})
	msg := "2FA 配置已保存"
	if prev {
		msg = "2FA 二次验证已关闭"
	}
	render(w, "settings.html", settingsPage(r, "", msg))
}

func handleSettingsNotifyTest(w http.ResponseWriter, r *http.Request) {
	username := currentUsername(r)
	s := store.GetUserSettings(username)
	channel := s.NotifyChannel
	var body struct {
		Channel string `json:"channel"`
	}
	if r.Header.Get("Content-Type") == "application/json" {
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
		if body.Channel == "bark" || body.Channel == "pushplus" {
			channel = body.Channel
		}
	}
	if channel == "" {
		channel = "bark"
	}
	if channel == "bark" && s.BarkKey == "" {
		errOut(w, "所选渠道未配置：请先在上方「推送渠道」填写 Bark 设备 Key 并保存")
		return
	}
	if channel == "pushplus" && s.PushplusToken == "" {
		errOut(w, "所选渠道未配置：请先在上方「推送渠道」填写 PushPlus Token 并保存")
		return
	}
	title, content := briefing.BuildBriefing()
	res := push.SendAlertText(s, channel, title, content)
	if !res.Ok {
		errOut(w, orStr(res.Error, "发送失败"))
		return
	}
	chName := "Bark"
	if channel == "pushplus" {
		chName = "PushPlus"
	}
	okOut(w, map[string]any{"message": fmt.Sprintf("已通过 %s 发送「%s」", chName, title)})
}

func orStr(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

// exportConfig 导出的配置结构（对齐 Node 版）
type exportConfig struct {
	App        string `json:"app"`
	Version    int    `json:"version"`
	ExportedAt string `json:"exported_at"`
	Tenants    []struct {
		Name        string `json:"name"`
		TenancyOcid string `json:"tenancy_ocid"`
		UserOcid    string `json:"user_ocid"`
		Fingerprint string `json:"fingerprint"`
		Region      string `json:"region"`
		PrivateKey  string `json:"private_key"`
		CustomName  string `json:"custom_name"`
		Cost        string `json:"cost"`
		AccountType string `json:"account_type"`
	} `json:"tenants"`
	Settings map[string]any `json:"settings"`
}

func handleSettingsExport(w http.ResponseWriter, r *http.Request) {
	username := currentUsername(r)
	var out exportConfig
	out.App = "oci-panel"
	out.Version = 1
	out.ExportedAt = time.Now().UTC().Format(time.RFC3339)
	for _, t := range store.ListTenants() {
		full := store.GetTenant(t.ID)
		privateKey := ""
		if full != nil && full.PrivateKeyEnc != "" {
			if key, err := cryptoutil.DecryptText(full.PrivateKeyEnc); err == nil {
				privateKey = key
			}
		}
		accountType := t.AccountType
		if accountType == "" {
			accountType = "FREE"
		}
		out.Tenants = append(out.Tenants, struct {
			Name        string `json:"name"`
			TenancyOcid string `json:"tenancy_ocid"`
			UserOcid    string `json:"user_ocid"`
			Fingerprint string `json:"fingerprint"`
			Region      string `json:"region"`
			PrivateKey  string `json:"private_key"`
			CustomName  string `json:"custom_name"`
			Cost        string `json:"cost"`
			AccountType string `json:"account_type"`
		}{
			Name: t.Name, TenancyOcid: t.TenancyOcid, UserOcid: t.UserOcid,
			Fingerprint: t.Fingerprint, Region: t.Region, PrivateKey: privateKey,
			CustomName: t.CustomName, Cost: t.Cost, AccountType: accountType,
		})
	}
	s := store.GetUserSettings(username)
	notifyTime := s.NotifyTime
	if notifyTime == "" {
		notifyTime = "09:00"
	}
	notifyChannel := s.NotifyChannel
	if notifyChannel == "" {
		notifyChannel = "bark"
	}
	twoFAChannel := s.TwoFAChannel
	if twoFAChannel == "" {
		twoFAChannel = "bark"
	}
	out.Settings = map[string]any{
		"bark_url": s.BarkURL, "bark_key": s.BarkKey, "pushplus_token": s.PushplusToken,
		"notify_channel": notifyChannel, "notify_enabled": s.NotifyEnabled,
		"notify_time": notifyTime, "notify_costs_daily": s.NotifyCostsDaily,
		"notify_account_health": s.NotifyAccountHealth, "notify_traffic_alert": s.NotifyTrafficAlert,
		"two_fa_channel": twoFAChannel,
	}
	fname := fmt.Sprintf("oci-panel-config-%s.json", time.Now().UTC().Format("2006-01-02"))
	w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`"`)
	jsonOut(w, out)
}

func handleSettingsImport(w http.ResponseWriter, r *http.Request) {
	username := currentUsername(r)
	var body struct {
		Data *exportConfig `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil || body.Data == nil {
		var direct exportConfig
		if err2 := json.NewDecoder(strings.NewReader("")).Decode(&direct); err2 != nil {
			errOut(w, "文件格式不正确（应为 OCI Panel 导出的配置文件）")
			return
		}
		body.Data = &direct
	}
	data := body.Data
	if data.App != "oci-panel" || data.Tenants == nil {
		errOut(w, "文件格式不正确（应为 OCI Panel 导出的配置文件）")
		return
	}

	added, updated, skipped := 0, 0, 0
	for _, t := range data.Tenants {
		tenancyOcid := strings.TrimSpace(t.TenancyOcid)
		userOcid := strings.TrimSpace(t.UserOcid)
		fingerprint := strings.TrimSpace(t.Fingerprint)
		region := strings.TrimSpace(t.Region)
		privateKey := strings.TrimSpace(t.PrivateKey)
		if tenancyOcid == "" || userOcid == "" || fingerprint == "" || region == "" {
			skipped++
			continue
		}
		name := strings.TrimSpace(t.Name)
		if name == "" {
			name = "tenant"
		}
		accountType := strings.TrimSpace(t.AccountType)
		if accountType == "" {
			accountType = "FREE"
		}
		var privateKeyEnc *string
		if strings.Contains(privateKey, "PRIVATE KEY") {
			if enc, err := cryptoutil.EncryptText(privateKey); err == nil {
				privateKeyEnc = &enc
			}
		}
		existingID := 0
		for _, x := range store.ListTenants() {
			if x.TenancyOcid == tenancyOcid {
				existingID = x.ID
				break
			}
		}
		if existingID != 0 {
			store.UpdateTenantFields(existingID, store.TenantFields{
				Name: &name, UserOcid: &userOcid, Fingerprint: &fingerprint, Region: &region,
				PrivateKeyEnc: privateKeyEnc,
				CustomName:    &t.CustomName, Cost: &t.Cost, AccountType: &accountType,
			})
			updated++
		} else {
			if privateKeyEnc == nil {
				skipped++ // 新租户缺少私钥无法添加
				continue
			}
			store.AddTenant(store.Tenant{
				Name: name, TenancyOcid: tenancyOcid, UserOcid: userOcid,
				Fingerprint: fingerprint, Region: region, PrivateKeyEnc: *privateKeyEnc,
				CustomName: t.CustomName, Cost: t.Cost, AccountType: accountType,
			})
			added++
		}
	}

	// 推送渠道 + 通知任务（不自动开启 2FA）
	if s := data.Settings; len(s) > 0 {
		store.UpdateUserSettings(username, func(cfg *store.Settings) {
			if v, ok := s["bark_url"].(string); ok {
				cfg.BarkURL = v
			}
			if v, ok := s["bark_key"].(string); ok {
				cfg.BarkKey = v
			}
			if v, ok := s["pushplus_token"].(string); ok {
				cfg.PushplusToken = v
			}
			if v, ok := s["notify_channel"].(string); ok {
				cfg.NotifyChannel = v
			}
			if v, ok := s["notify_time"].(string); ok {
				cfg.NotifyTime = v
			}
			if v, ok := s["notify_enabled"].(bool); ok {
				cfg.NotifyEnabled = v
			}
			if v, ok := s["notify_costs_daily"].(bool); ok {
				cfg.NotifyCostsDaily = v
			}
			if v, ok := s["notify_account_health"].(bool); ok {
				cfg.NotifyAccountHealth = v
			}
			if v, ok := s["notify_traffic_alert"].(bool); ok {
				cfg.NotifyTrafficAlert = v
			}
			if v, ok := s["two_fa_channel"].(string); ok {
				cfg.TwoFAChannel = v
			}
			cfg.TwoFAEnabled = false
		})
	}

	parts := []string{fmt.Sprintf("新增 %d 个租户", added), fmt.Sprintf("更新 %d 个", updated)}
	if skipped > 0 {
		parts = append(parts, fmt.Sprintf("跳过 %d 个（数据不完整）", skipped))
	}
	parts = append(parts, "推送渠道与通知设置已同步，2FA 需手动重新开启")
	okOut(w, map[string]any{"message": strings.Join(parts, "，")})
}
