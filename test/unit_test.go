package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	golangIPSentry "github.com/pardnchiu/golang-ip-sentry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testConfig = golangIPSentry.Config{
	Redis: golangIPSentry.Redis{
		Host:     "localhost",
		Port:     6379,
		Password: "0123456789",
		DB:       0, // 使用測試專用 DB
	},
	Log: &golangIPSentry.Log{
		Path:    "./logs/test",
		Stdout:  false,
		MaxSize: 16,
	},
	Parameter: golangIPSentry.Parameter{
		BlockToBan:             3,
		BlockTimeMin:           30 * time.Minute,
		BlockTimeMax:           1800 * time.Minute,
		RateLimitNormal:        10,
		RateLimitSuspicious:    5,
		RateLimitDangerous:     3,
		SessionMultiIP:         2,
		IPMultiDevice:          3,
		DeviceMultiIP:          2,
		LoginFailure:           3,
		NotFound404:            5,
		ScoreSuspicious:        30,
		ScoreDangerous:         60,
		ScoreSessionMultiIP:    20,
		ScoreIPMultiDevice:     25,
		ScoreDeviceMultiIP:     15,
		ScoreFpMultiSession:    40,
		ScoreGeoHopping:        15,
		ScoreGeoFrequentSwitch: 20,
		ScoreGeoRapidChange:    25,
		ScoreIntervalRequest:   20,
		ScoreFrequencyRequest:  25,
		ScoreLongConnection:    15,
	},
}

func setupTestGuardian(t *testing.T) *golangIPSentry.IPGuardian {
	guardian, err := golangIPSentry.New(testConfig)
	require.NoError(t, err)

	// 清理測試 Redis 資料
	// guardian.Redis.FlushDB(context.Background())

	return guardian
}

func teardownTestGuardian(guardian *golangIPSentry.IPGuardian) {
	if guardian != nil {
		// guardian.Redis.FlushDB(context.Background())
		guardian.Close()
	}
}

// TestIPGuardianInitialization 測試初始化
func TestIPGuardianInitialization(t *testing.T) {
	guardian := setupTestGuardian(t)
	defer teardownTestGuardian(guardian)

	assert.NotNil(t, guardian)
	assert.NotNil(t, guardian.Redis)
	assert.NotNil(t, guardian.Logger)
	assert.NotNil(t, guardian.Manager)
	assert.NotNil(t, guardian.Manager.Allow)
	assert.NotNil(t, guardian.Manager.Block)
	assert.NotNil(t, guardian.Manager.Deny)
}

// TestRedisConnection 測試 Redis 連線
func TestRedisConnection(t *testing.T) {
	guardian := setupTestGuardian(t)
	defer teardownTestGuardian(guardian)

	result := guardian.Redis.Ping(context.Background())
	assert.NoError(t, result.Err())
}

// TestAllowIPManager 測試信任 IP 管理
func TestAllowIPManager(t *testing.T) {
	guardian := setupTestGuardian(t)
	defer teardownTestGuardian(guardian)

	testIP := "192.168.1.100"
	testTag := "測試信任 IP"

	// 測試加入信任 IP
	err := guardian.Manager.Allow.Add(testIP, testTag)
	assert.NoError(t, err)

	// 測試檢查信任 IP
	isTrusted := guardian.Manager.Allow.Check(testIP)
	assert.True(t, isTrusted)

	// 測試非信任 IP
	isNotTrusted := guardian.Manager.Allow.Check("1.2.3.4")
	assert.False(t, isNotTrusted)
}

// TestDenyIPManager 測試黑名單 IP 管理
func TestDenyIPManager(t *testing.T) {
	guardian := setupTestGuardian(t)
	defer teardownTestGuardian(guardian)

	testIP := "1.2.3.4"
	testReason := "測試惡意 IP"

	// 測試加入黑名單 IP
	err := guardian.Manager.Deny.Add(testIP, testReason)
	assert.NoError(t, err)

	// 測試檢查黑名單 IP
	isBanned := guardian.Manager.Deny.Check(testIP)
	assert.True(t, isBanned)

	// 測試非黑名單 IP
	isNotBanned := guardian.Manager.Deny.Check("192.168.1.1")
	assert.False(t, isNotBanned)
}

// TestBlockIPManager 測試封鎖 IP 管理
func TestBlockIPManager(t *testing.T) {
	guardian := setupTestGuardian(t)
	defer teardownTestGuardian(guardian)

	testIP := "5.6.7.8"
	testReason := "測試可疑活動"

	// 測試加入封鎖 IP
	err := guardian.Manager.Block.Add(testIP, testReason)
	assert.NoError(t, err)

	// 測試檢查封鎖 IP
	isBlocked := guardian.Manager.Block.IsBlock(testIP)
	assert.True(t, isBlocked)

	// 測試非封鎖 IP
	isNotBlocked := guardian.Manager.Block.IsBlock("192.168.1.1")
	assert.False(t, isNotBlocked)
}

// TestIPGuardianCheck 測試主要檢查功能
func TestIPGuardianCheck(t *testing.T) {
	guardian := setupTestGuardian(t)
	defer teardownTestGuardian(guardian)

	t.Run("正常 IP 通過", func(t *testing.T) {
		req := createTestRequest("192.168.1.1")
		w := httptest.NewRecorder()

		result := guardian.Check(req, w)
		assert.True(t, result.Success)
		assert.Equal(t, http.StatusOK, result.StatusCode)
	})

	t.Run("信任 IP 通過", func(t *testing.T) {
		trustIP := "192.168.1.100"
		guardian.Manager.Allow.Add(trustIP, "測試信任 IP")

		req := createTestRequest(trustIP)
		w := httptest.NewRecorder()

		result := guardian.Check(req, w)
		assert.True(t, result.Success)
		assert.Equal(t, http.StatusOK, result.StatusCode)
	})

	t.Run("黑名單 IP 拒絕", func(t *testing.T) {
		banIP := "1.2.3.4"
		guardian.Manager.Deny.Add(banIP, "測試惡意 IP")

		req := createTestRequest(banIP)
		w := httptest.NewRecorder()

		result := guardian.Check(req, w)
		assert.False(t, result.Success)
		assert.Equal(t, http.StatusForbidden, result.StatusCode)
		assert.Contains(t, result.Error, "banned")
	})

	t.Run("封鎖 IP 拒絕", func(t *testing.T) {
		blockIP := "5.6.7.8"
		guardian.Manager.Block.Add(blockIP, "測試可疑活動")

		req := createTestRequest(blockIP)
		w := httptest.NewRecorder()

		result := guardian.Check(req, w)
		assert.False(t, result.Success)
		assert.Equal(t, http.StatusForbidden, result.StatusCode)
		assert.Contains(t, result.Error, "blocked")
	})
}

// TestRateLimit 測試速率限制
// func TestRateLimit(t *testing.T) {
// 	guardian := setupTestGuardian(t)
// 	defer teardownTestGuardian(guardian)

// 	testIP := "10.0.0.1"

// 	// 連續請求測試正常速率限制
// 	for i := 0; i < testConfig.Parameter.RateLimitNormal; i++ {
// 		req := createTestRequest(testIP)
// 		w := httptest.NewRecorder()

// 		result := guardian.Check(req, w)
// 		if i < testConfig.Parameter.RateLimitNormal-1 {
// 			assert.True(t, result.Success, "請求 %d 應該成功", i+1)
// 		}
// 	}

// 	// 超過限制的請求應該被拒絕
// 	req := createTestRequest(testIP)
// 	w := httptest.NewRecorder()
// 	result := guardian.Check(req, w)
// 	assert.False(t, result.Success)
// 	assert.Contains(t, result.Error, "rate limit")
// }

// TestLoginFailure 測試登入失敗記錄
func TestLoginFailure(t *testing.T) {
	guardian := setupTestGuardian(t)
	defer teardownTestGuardian(guardian)

	req := createTestRequest("10.0.0.2")
	w := httptest.NewRecorder()

	// 記錄登入失敗
	err := guardian.LoginFailure(w, req)
	assert.NoError(t, err)
}

// TestNotFound404 測試 404 錯誤記錄
func TestNotFound404(t *testing.T) {
	guardian := setupTestGuardian(t)
	defer teardownTestGuardian(guardian)

	req := createTestRequest("10.0.0.3")
	w := httptest.NewRecorder()

	// 記錄 404 錯誤
	err := guardian.NotFound404(w, req)
	assert.NoError(t, err)
}

// TestMiddleware 測試中間件
func TestMiddleware(t *testing.T) {
	guardian := setupTestGuardian(t)
	defer teardownTestGuardian(guardian)

	t.Run("HTTP 中間件正常請求", func(t *testing.T) {
		handler := guardian.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		}))

		req := createTestRequest("10.0.0.5")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "success", w.Body.String())
	})

	t.Run("HTTP 中間件黑名單請求", func(t *testing.T) {
		banIP := "1.2.3.5"
		guardian.Manager.Deny.Add(banIP, "測試黑名單")

		handler := guardian.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		}))

		req := createTestRequest(banIP)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "error")
	})
}

// TestConcurrentRequests 測試並發請求
// func TestConcurrentRequests(t *testing.T) {
// 	guardian := setupTestGuardian(t)
// 	defer teardownTestGuardian(guardian)

// 	const numRequests = 50
// 	const numWorkers = 10

// 	results := make(chan bool, numRequests)
// 	requestChan := make(chan int, numRequests)

// 	// 填充請求通道
// 	for i := 0; i < numRequests; i++ {
// 		requestChan <- i
// 	}
// 	close(requestChan)

// 	// 啟動 worker goroutines
// 	for w := 0; w < numWorkers; w++ {
// 		go func() {
// 			for i := range requestChan {
// 				req := createTestRequest(fmt.Sprintf("10.0.1.%d", i%10))
// 				w := httptest.NewRecorder()

// 				result := guardian.Check(req, w)
// 				results <- result.Success
// 			}
// 		}()
// 	}

// 	// 收集結果
// 	successCount := 0
// 	for i := 0; i < numRequests; i++ {
// 		if <-results {
// 			successCount++
// 		}
// 	}

// 	// 大部分請求應該成功（考慮速率限制）
// 	assert.Greater(t, successCount, numRequests/2)
// }

// TestIPParsing 測試 IP 解析
func TestIPParsing(t *testing.T) {
	guardian := setupTestGuardian(t)
	defer teardownTestGuardian(guardian)

	testCases := []struct {
		name            string
		headers         map[string]string
		remoteAddr      string
		expectedIP      string
		expectedPrivate bool
	}{
		{
			name:            "Cloudflare IP",
			headers:         map[string]string{"CF-Connecting-IP": "203.64.1.1"},
			remoteAddr:      "127.0.0.1:12345",
			expectedIP:      "203.64.1.1",
			expectedPrivate: false,
		},
		{
			name:            "X-Forwarded-For",
			headers:         map[string]string{"X-Forwarded-For": "192.168.1.100"},
			remoteAddr:      "127.0.0.1:12345",
			expectedIP:      "192.168.1.100",
			expectedPrivate: true,
		},
		{
			name:            "X-Real-IP",
			headers:         map[string]string{"X-Real-IP": "1.2.3.4"},
			remoteAddr:      "127.0.0.1:12345",
			expectedIP:      "1.2.3.4",
			expectedPrivate: false,
		},
		{
			name:            "RemoteAddr only",
			headers:         map[string]string{},
			remoteAddr:      "10.0.0.1:12345",
			expectedIP:      "10.0.0.1",
			expectedPrivate: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tc.remoteAddr

			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}
		})
	}
}

// TestUserAgentParsing 測試 User-Agent 解析
func TestUserAgentParsing(t *testing.T) {
	guardian := setupTestGuardian(t)
	defer teardownTestGuardian(guardian)

	testCases := []struct {
		userAgent  string
		platform   string
		browser    string
		deviceType string
	}{
		{
			userAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			platform:   "Windows",
			browser:    "Chrome",
			deviceType: "Desktop",
		},
		{
			userAgent:  "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
			platform:   "iOS",
			browser:    "Safari",
			deviceType: "Mobile",
		},
		{
			userAgent:  "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
			platform:   "iOS",
			browser:    "Safari",
			deviceType: "Tablet",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.deviceType, func(t *testing.T) {
			req := createTestRequest("10.0.0.1")
			req.Header.Set("User-Agent", tc.userAgent)
		})
	}
}

// Benchmark 效能測試
func BenchmarkIPGuardianCheck(b *testing.B) {
	guardian := setupTestGuardian(&testing.T{})
	defer teardownTestGuardian(guardian)

	req := createTestRequest("10.0.0.1")
	w := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		guardian.Check(req, w)
	}
}

// 輔助函數
func createTestRequest(ip string) *http.Request {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Test) TestBrowser/1.0")
	req.RemoteAddr = "127.0.0.1:12345"
	return req
}

// 測試用的 HTTP 處理器
func testHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
