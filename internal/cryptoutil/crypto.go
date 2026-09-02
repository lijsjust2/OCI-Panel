package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/scrypt"

	"oci-panel/internal/config"
)

var aesKey []byte

// API 私钥的加密密钥：首次启动自动生成，保存在 data/secret.key
func getKey() ([]byte, error) {
	if aesKey != nil {
		return aesKey, nil
	}
	if b, err := os.ReadFile(config.SecretFile); err == nil {
		aesKey = b
		return aesKey, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(config.SecretFile, b, 0o600); err != nil {
		return nil, err
	}
	aesKey = b
	return aesKey, nil
}

// ---- 登录密码（scrypt，与 Node 版格式一致：salt:hash 十六进制） ----

func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 64)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%s", hex(salt), hex(hash)), nil
}

func hex(b []byte) string {
	const chars = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, v := range b {
		out = append(out, chars[v>>4], chars[v&0x0f])
	}
	return string(out)
}

func fromHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("非法十六进制串")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi := hexVal(s[i*2])
		lo := hexVal(s[i*2+1])
		if hi < 0 || lo < 0 {
			return nil, fmt.Errorf("非法十六进制字符")
		}
		out[i] = byte(hi<<4 | lo)
	}
	return out, nil
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func VerifyPassword(password, stored string) bool {
	parts := strings.SplitN(stored, ":", 2)
	if len(parts) != 2 {
		// 格式无效时也执行一次 scrypt，消除响应时序差
		_, _ = scrypt.Key([]byte(password), make([]byte, 16), 16384, 8, 1, 64)
		return false
	}
	salt, err1 := fromHex(parts[0])
	want, err2 := fromHex(parts[1])
	if err1 != nil || err2 != nil {
		_, _ = scrypt.Key([]byte(password), make([]byte, 16), 16384, 8, 1, 64)
		return false
	}
	got, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 64)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// DummyHash 启动时预计算的哑哈希：用户不存在时用它跑一次完整的
// VerifyPassword，使响应时间与真实用户一致，防止时序枚举用户名。
var DummyHash = func() string {
	h, _ := HashPassword("dummy-password-for-timing")
	return h
}()

// ---- API 私钥存储（AES-256-GCM，与 Node 版格式一致：base64(iv).base64(tag).base64(enc)） ----

func EncryptText(text string) (string, error) {
	key, err := getKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	enc := gcm.Seal(nil, iv, []byte(text), nil)
	tag, data := enc[len(enc)-gcm.Overhead():], enc[:len(enc)-gcm.Overhead()]
	b64 := base64.StdEncoding.EncodeToString
	return b64(iv) + "." + b64(tag) + "." + b64(data), nil
}

func DecryptText(stored string) (string, error) {
	key, err := getKey()
	if err != nil {
		return "", err
	}
	parts := strings.Split(stored, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("密文格式错误")
	}
	dec := base64.StdEncoding.DecodeString
	iv, err1 := dec(parts[0])
	tag, err2 := dec(parts[1])
	data, err3 := dec(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return "", fmt.Errorf("密文 base64 解码失败")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, iv, append(data, tag...), nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// ---- 基于密码的加密/解密（用于配置导出/导入）----

const (
	encMagic = "OCIPANEL\x01" // 文件头标识 + 版本号
	saltLen  = 32             // scrypt salt 长度
	nonceLen = 12             // AES-GCM nonce 长度
)

// EncryptWithPassword 用密码加密任意数据，输出二进制格式（直接打开为乱码）
func EncryptWithPassword(plaintext []byte, password string) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	enc := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(encMagic)+saltLen+nonceLen+len(enc))
	out = append(out, []byte(encMagic)...)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, enc...)
	return out, nil
}

// DecryptWithPassword 用密码解密 EncryptWithPassword 产生的数据
func DecryptWithPassword(data []byte, password string) ([]byte, error) {
	headerLen := len(encMagic) + saltLen + nonceLen
	if len(data) < headerLen {
		return nil, fmt.Errorf("文件格式错误或已损坏")
	}
	if string(data[:len(encMagic)]) != encMagic {
		return nil, fmt.Errorf("文件格式不正确（非 OCI Panel 加密配置）")
	}
	salt := data[len(encMagic) : len(encMagic)+saltLen]
	nonce := data[len(encMagic)+saltLen : headerLen]
	ciphertext := data[headerLen:]
	key, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("密码错误或文件已损坏")
	}
	return plain, nil
}