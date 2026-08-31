package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"oci-panel/internal/config"
)

const cookieName = "ocipanel_session"
const maxAge = 24 * time.Hour

// 无状态签名 Cookie：payload = username|userId|expiryUnix，HMAC-SHA256 签名。
// 密钥持久化在 data/session.secret，重启后登录态不失效（对齐 Node 版 express-session 行为）。

func sign(payload string) string {
	mac := hmac.New(sha256.New, []byte(config.SessionSecret))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func createValue(username string, userID int) string {
	payload := username + "|" + strconv.Itoa(userID) + "|" + strconv.FormatInt(time.Now().Add(maxAge).Unix(), 10)
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sign(payload)
}

func parseValue(v string) (username string, userID int, ok bool) {
	parts := strings.SplitN(v, ".", 2)
	if len(parts) != 2 {
		return "", 0, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", 0, false
	}
	payload := string(raw)
	if !hmac.Equal([]byte(sign(payload)), []byte(parts[1])) {
		return "", 0, false
	}
	fields := strings.Split(payload, "|")
	if len(fields) != 3 {
		return "", 0, false
	}
	uid, err := strconv.Atoi(fields[1])
	if err != nil {
		return "", 0, false
	}
	exp, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", 0, false
	}
	return fields[0], uid, true
}

// Login 写入登录会话（重建：签发全新 Cookie，防会话固定攻击）
func Login(w http.ResponseWriter, username string, userID int) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    createValue(username, userID),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(maxAge.Seconds()),
	})
}

func Logout(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// Current 从请求解析当前登录用户
func Current(r *http.Request) (username string, userID int, ok bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", 0, false
	}
	return parseValue(c.Value)
}
