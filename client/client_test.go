package client

import (
	"regexp"
	"testing"
	"time"
)

// TestTimeRFC3339 测试TimeRFC3339函数
func TestTimeRFC3339(t *testing.T) {
	result := TimeRFC3339()
	// 打印返回结果
	t.Logf("TimeRFC3339() returned: %s", *result)
	if result == nil {
		t.Fatal("TimeRFC3339 should return a non-nil string pointer")
	}

	// 验证返回的字符串是否符合RFC3339格式
	timeObj, err := time.Parse(time.RFC3339, *result)
	if err != nil {
		t.Errorf("TimeRFC3339 returned invalid RFC3339 format: %s", *result)
	}

	// 验证返回的时间是否在当前时间附近（10秒内）
	currentTime := time.Now()
	timeDiff := currentTime.Sub(timeObj)
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}
	if timeDiff > 10*time.Second {
		t.Errorf("TimeRFC3339 returned time %s which is more than 10 seconds away from current time", *result)
	}
}

// TestGenerateNonce 测试GenerateNonce函数
func TestGenerateNonce(t *testing.T) {
	result := GenerateNonce()
	// 打印返回结果
	t.Logf("GenerateNonce() returned: %s", *result)
	if result == nil {
		t.Fatal("GenerateNonce should return a non-nil string pointer")
	}

	// 验证返回的字符串是否为16位十六进制
	regex := regexp.MustCompile(`^[0-9a-f]{16}$`)
	if !regex.MatchString(*result) {
		t.Errorf("GenerateNonce returned invalid nonce: %s, expected 16 hexadecimal characters", *result)
	}

	// 验证每次调用返回的nonce是否不同
	result2 := GenerateNonce()
	// 打印第二次返回结果
	t.Logf("GenerateNonce() returned again: %s", *result2)
	if *result == *result2 {
		t.Error("GenerateNonce should return different nonce values for different calls")
	}
}

// TestGenerateSignature 测试GenerateSignature函数
func TestGenerateSignature(t *testing.T) {
	// 准备测试数据
	body := "{\"winKey\":\"npJi367lttpwmD1goZ1yOQ\",\"arch\":\"x64\",\"versionCode\":1,\"appointVersionCode\":0,\"devModelKey\":\"\",\"devKey\":\"\"}"
	nonce := "60ba668ab9f327ee"
	secretKey := "PEbdHFGC0uO_Pch7XWBQTMsFRxKPQAM2565eP8LJ3gc"
	timestamp := "2026-01-05T05:11:04Z"
	uri := "/v1/win/upgrade"

	result := GenerateSignature(&body, &nonce, &secretKey, &timestamp, &uri)
	// 打印返回结果
	t.Logf("GenerateSignature() returned: %s", *result)
	if result == nil {
		t.Fatal("GenerateSignature should return a non-nil string pointer")
	}

	// 验证返回的签名是否符合预期长度
	if len(*result) != 32 {
		t.Errorf("GenerateSignature returned signature of wrong length: %d, expected 32", len(*result))
	}

	// 验证签名格式是否为32位十六进制
	regex := regexp.MustCompile(`^[0-9a-f]{32}$`)
	if !regex.MatchString(*result) {
		t.Errorf("GenerateSignature returned invalid signature format: %s", *result)
	}

}
