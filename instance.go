package golangIPSentry

import (
	"context"
	"fmt"
	"net/http"

	goLogger "github.com/pardnchiu/go-logger"
	"github.com/redis/go-redis/v9"
)

func New(c Config) (*IPGuardian, error) {
	c.Log = validLoggerConfig(c)

	logger, err := goLogger.New(c.Log)
	if err != nil {
		return nil, fmt.Errorf("Failed to initialize `pardnchiu/go-logger`: %w", err)
	}

	if c.Redis.Host == "" {
		c.Redis.Host = "localhost"
	}

	if c.Redis.Port <= 0 || c.Redis.Port > 65535 {
		c.Redis.Port = 6379
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", c.Redis.Host, c.Redis.Port),
		Password: c.Redis.Password,
		DB:       c.Redis.DB,
	})
	if _, err := redisClient.Ping(context.Background()).Result(); err != nil {
		return nil, logger.Error(err, "Failed to connect Redis")
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
		Config:  &c,
		Redis:   redisClient,
		Logger:  logger,
		// AbuseIPDBApi: abuseIPDBApi,
	}

	instance.Manager = &Manager{
		Allow: instance.newAllowManager(),
		Deny:  instance.newDenyIPManager(),
		Block: instance.newBlocIPkManager(),
	}

	instance.GeoLite2 = instance.newGeoLite2()

	return instance, nil
}

func (i *IPGuardian) Close() error {
	if i.Redis != nil {
		if err := i.Redis.Close(); err != nil {
			return err
		}
	}
	if i.GeoLite2 != nil {
		i.GeoLite2.close()
	}

	i.Logger.Close()

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

	if device.Is.Block {
		// * this device is banned, return error
		return IPGuardianResult{
			Success:    false,
			StatusCode: http.StatusForbidden,
			Error:      "Device is blocked, IP: " + device.IP.Address,
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

	if i.Config.Parameter.BlockToBan <= 0 {
		i.Config.Parameter.BlockToBan = 8
	}

	if i.Config.Parameter.RateLimitNormal <= 0 {
		i.Config.Parameter.RateLimitNormal = 100
	}
	if i.Config.Parameter.RateLimitSuspicious <= 0 {
		i.Config.Parameter.RateLimitSuspicious = 50
	}
	if i.Config.Parameter.RateLimitDangerous <= 0 {
		i.Config.Parameter.RateLimitDangerous = 20
	}

	if device.Is.Block && device.IP.BlockCount >= i.Config.Parameter.BlockToBan {
		i.Manager.Deny.Add(device.IP.Address, "Device is blocked and continue to request, IP: "+device.IP.Address)
		return IPGuardianResult{
			Success:    false,
			StatusCode: http.StatusForbidden,
			Error:      "Device is banned, IP: " + device.IP.Address,
		}
	}

	score, err := i.dynamicScore(device)
	if err != nil {
		// TODO: 後續要改寫，不能直接通過
		i.Logger.Error(err, "Failed to detect suspicious activity")
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

func validLoggerConfig(c Config) *Log {
	if c.Log == nil {
		c.Log = &Log{
			Path:    defaultLogPath,
			Stdout:  false,
			MaxSize: defaultLogMaxSize,
		}
	}
	if c.Log.Path == "" {
		c.Log.Path = defaultLogPath
	}
	if c.Log.MaxSize <= 0 {
		c.Log.MaxSize = defaultLogMaxSize
	}
	if c.Log.MaxBackup <= 0 {
		c.Log.MaxBackup = defaultLogMaxBackup
	}
	return c.Log
}
