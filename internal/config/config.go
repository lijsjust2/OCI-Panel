package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

var (
	Port          string
	DataDir       string
	DBFile        string
	SecretFile    string
	SessionSecret string
)

func init() {
	DataDir = envOr("DATA_DIR", "./data")
	if err := os.MkdirAll(DataDir, 0o700); err != nil {
		panic(fmt.Errorf("创建数据目录失败: %w", err))
	}
	Port = envOr("PORT", "8800")
	SecretFile = filepath.Join(DataDir, "secret.key")
	SessionSecret = envOr("SESSION_SECRET", loadOrCreateSecret(filepath.Join(DataDir, "session.secret")))
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// session 密钥持久化，避免每次重启后登录态失效
func loadOrCreateSecret(file string) string {
	if b, err := os.ReadFile(file); err == nil {
		if s := string(b); s != "" {
			return s
		}
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	s := hex.EncodeToString(b)
	_ = os.WriteFile(file, []byte(s), 0o600)
	return s
}
