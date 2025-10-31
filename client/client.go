package client

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"
)

// TimeRFC3339 生成RFC3339格式的时间字符串
// TimeRFC3339 generates a time string in RFC3339 format
func TimeRFC3339() *string {
	timestamp := time.Now().Format(time.RFC3339)
	return &timestamp
}

// GenerateNonce 生成随机Nonce (16位十六进制)
// GenerateNonce generates a random Nonce (16-bit hexadecimal)
func GenerateNonce() *string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	str := hex.EncodeToString(bytes)
	return &str
}

// GenerateSignature 生成请求签名
// GenerateSignature generates a request signature
func GenerateSignature(body, nonce, secretKey, timestamp, uri *string) *string {
	var parts []string

	if *body != "" {
		parts = append(parts, "body="+*body)
	}

	parts = append(parts,
		"nonce="+*nonce,
		"secretKey="+*secretKey,
		"timestamp="+*timestamp,
		"url="+*uri,
	)

	signStr := strings.Join(parts, "&")
	hash := md5.Sum([]byte(signStr))
	str := hex.EncodeToString(hash[:])
	return &str
}
