package golangIPGuardian

import (
	"context"
	"fmt"
	"net/http"

	"github.com/redis/go-redis/v9"
)

func New(c *Config) (*IPGuardian, error) {
	if c == nil {
		c = &Config{
			Redis: Redis{
				Host:     "localhost",
				Port:     6379,
				Password: "",
				DB:       0,
			},
			Log: LogConfig{
				Path:    "./logs/golangIPGuardian",
				Stdout:  false,
				MaxSize: 16 * 1024 * 1024,
			},
			Parameter: Parameter{
				BlockToBan:             8,          // 封鎖到禁止的次數
				BlockTimeMin:           3600,       // 最小封鎖時間（秒）
				BlockTimeMax:           86400 * 30, // 最大封鎖時間（秒）
				RateLimitNormal:        100,        // 正常請求速率限制
				RateLimitSuspicious:    50,         // 可疑請求速率限制
				RateLimitDangerous:     20,         // 危險請求速率限制
				SessionMultiIP:         4,          // 同一 Session 多 IP 次數限制
				IPMultiDevice:          8,          // 同一 IP 多設備次數限制
				DeviceMultiIP:          4,          // 同一設備多 IP 次數限制
				LoginFailure:           4,          // 登入失敗次數限制
				NotFound404:            8,          // 404 錯誤次數限制
				ScoreNormal:            0,          // 正常分數
				ScoreSuspicious:        50,         // 可疑分數
				ScoreDangerous:         80,         // 危險分數
				ScoreDeviceMultiIP:     15,         // 設備多 IP 分數
				ScoreIPMultiDevice:     20,         // IP 多設備分數
				ScoreSessionMultiIP:    25,         // Session 多 IP 分數
				ScoreFpMultiSession:    50,         // 指紋多 Session 分數
				ScoreGeoHopping:        15,         // 地理位置跳躍分數
				ScoreGeoFrequentSwitch: 20,         // 地理位置頻繁切換分數
				ScoreGeoRapidChange:    25,         // 地理位置快速變化分數
				ScoreLongConnection:    15,         // 長連接分數
				ScoreIntervalRequest:   25,         // 請求間隔分數
			},
		}
	}

	if c.Redis.Host == "" {
		c.Redis.Host = "localhost"
	}

	if c.Redis.Port <= 0 || c.Redis.Port > 65535 {
		c.Redis.Port = 6379
	}

	if c.Log.MaxSize <= 0 {
		c.Log.MaxSize = 16 * 1024 * 1024
	} else if c.Log.MaxSize < 1024*1024 {
		c.Log.MaxSize = c.Log.MaxSize * 1024 * 1024
	}

	if c.Parameter.BlockToBan <= 0 {
		c.Parameter.BlockToBan = 8
	}
	if c.Parameter.SessionMultiIP <= 0 {
		c.Parameter.SessionMultiIP = 4
	}
	if c.Parameter.IPMultiDevice <= 0 {
		c.Parameter.IPMultiDevice = 8
	}
	if c.Parameter.DeviceMultiIP <= 0 {
		c.Parameter.DeviceMultiIP = 4
	}
	if c.Parameter.LoginFailure <= 0 {
		c.Parameter.LoginFailure = 4
	}
	if c.Parameter.NotFound404 <= 0 {
		c.Parameter.NotFound404 = 8
	}
	if c.Parameter.RateLimitNormal <= 0 {
		c.Parameter.RateLimitNormal = 100
	}
	if c.Parameter.RateLimitSuspicious <= 0 {
		c.Parameter.RateLimitSuspicious = 50
	}
	if c.Parameter.RateLimitDangerous <= 0 {
		c.Parameter.RateLimitDangerous = 20
	}
	if c.Parameter.ScoreNormal <= 0 {
		c.Parameter.ScoreNormal = 0
	}
	if c.Parameter.ScoreSuspicious <= 0 {
		c.Parameter.ScoreSuspicious = 50
	}
	if c.Parameter.ScoreDangerous <= 0 {
		c.Parameter.ScoreDangerous = 80
	}
	if c.Parameter.ScoreDeviceMultiIP <= 0 {
		c.Parameter.ScoreDeviceMultiIP = 15
	}
	if c.Parameter.ScoreIPMultiDevice <= 0 {
		c.Parameter.ScoreIPMultiDevice = 20
	}
	if c.Parameter.ScoreSessionMultiIP <= 0 {
		c.Parameter.ScoreSessionMultiIP = 25
	}
	if c.Parameter.ScoreFpMultiSession <= 0 {
		c.Parameter.ScoreFpMultiSession = 50
	}
	if c.Parameter.ScoreGeoHopping <= 0 {
		c.Parameter.ScoreGeoHopping = 15
	}
	if c.Parameter.ScoreGeoFrequentSwitch <= 0 {
		c.Parameter.ScoreGeoFrequentSwitch = 20
	}
	if c.Parameter.ScoreGeoRapidChange <= 0 {
		c.Parameter.ScoreGeoRapidChange = 25
	}
	if c.Parameter.ScoreLongConnection <= 0 {
		c.Parameter.ScoreLongConnection = 15
	}
	if c.Parameter.ScoreIntervalRequest <= 0 {
		c.Parameter.ScoreIntervalRequest = 25
	}

	logger, err := newLogger(c.Log)
	if err != nil {
		return nil, logger.error("Failed to init logger", err.Error())
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", c.Redis.Host, c.Redis.Port),
		Password: c.Redis.Password,
		DB:       c.Redis.DB,
	})

	// geoipDB, err := geoip2.Open("GeoLite2-Country.mmdb")
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to open GeoIP database: %w", err)
	// }

	if _, err := redisClient.Ping(context.Background()).Result(); err != nil {
		return nil, logger.error("Failed to connect Redis", err.Error())
	}

	// var abuseIPDBApi *AbuseIPDBApi
	// if c.AbuseIPDBToken != "" {
	// 	abuseIPDBApi = &AbuseIPDBApi{
	// 		Context: context.Background(),
	// 		IsPaid:  c.AbuseIPDBIsPaid,
	// 		Redis:   redisClient,
	// 		HTTP:    &http.Client{Timeout: 10 * time.Second},
	// 		Token:   c.AbuseIPDBToken,
	// 		Logger:  logger,
	// 	}
	// }

	instance := &IPGuardian{
		Context: context.Background(),
		Config:  c,
		Redis:   redisClient,
		Logger:  logger,
	}

	instance.Manager = &Manager{
		Trust: instance.newTrustManager(),
		Ban:   instance.newBanManager(),
		Block: instance.newBlockManager(),
	}

	return instance, nil
}

func (i *IPGuardian) Close() error {
	if i.Redis == nil {
		if err := i.Redis.Close(); err != nil {
			return err
		}
	}

	i.Logger.close()

	return nil
}

type IPGuardianResult struct {
	Success    bool   `json:"success"`
	StatusCode int    `json:"status_code"`
	Error      string `json:"error"`
}

func (i *IPGuardian) Check(r *http.Request, w http.ResponseWriter) IPGuardianResult {
	device, err := i.getDevice(w, r)
	if err != nil {
		return IPGuardianResult{
			Success:    false,
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to get device info",
		}
	}

	if device.Is.Trust {
		// * this device is trusted, skip further checks
		return IPGuardianResult{
			Success:    true,
			StatusCode: http.StatusOK,
		}
	}

	if device.Is.Ban {
		// * this device is banned, return error
		return IPGuardianResult{
			Success:    false,
			StatusCode: http.StatusForbidden,
			Error:      "Device is banned, IP: " + device.IP.Address,
		}
	}

	// * auto add to ban list if device is blocked and continue request
	if device.Is.Block && device.IP.BlockCount >= i.Config.Parameter.BlockToBan {
		i.Manager.Ban.Add(device.IP.Address, "Device is blocked and continue to request, IP: "+device.IP.Address)
		return IPGuardianResult{
			Success:    false,
			StatusCode: http.StatusForbidden,
			Error:      "Device is banned, IP: " + device.IP.Address,
		}
	}

	score, err := i.dynamicScore(device)
	if err != nil {
		// TODO: 後續要改寫，不能直接通過
		i.Logger.error("Failed to detect suspicious activity", err.Error())
	}

	if score.IsBlock {
		// * dynamicScore 已自動添加至 blocklist，不需重複添加
		return IPGuardianResult{
			Success:    false,
			StatusCode: http.StatusForbidden,
			Error:      "Device is blocked, IP: " + device.IP.Address,
		}
	}

	if score.IsDangerous && device.IP.RequestCount >= i.Config.Parameter.RateLimitDangerous {
		return IPGuardianResult{
			Success:    false,
			StatusCode: http.StatusForbidden,
			Error:      "Device is reached rate limit (Dangerous), IP: " + device.IP.Address,
		}
	}
	if score.IsSuspicious && device.IP.RequestCount >= i.Config.Parameter.RateLimitSuspicious {
		return IPGuardianResult{
			Success:    false,
			StatusCode: http.StatusForbidden,
			Error:      "Device is reached rate limit (Suspicious), IP: " + device.IP.Address,
		}
	}
	if device.IP.RequestCount >= i.Config.Parameter.RateLimitNormal {
		return IPGuardianResult{
			Success:    false,
			StatusCode: http.StatusForbidden,
			Error:      "Device is reached rate limit (Normal), IP: " + device.IP.Address,
		}
	}

	// TODO: AbuseIPDB 檢查未完成

	return IPGuardianResult{
		Success:    true,
		StatusCode: http.StatusOK,
	}
}
