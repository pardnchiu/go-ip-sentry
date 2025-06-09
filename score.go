// TODO 需花時間重新檢查
package golangIPSentry

import (
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type ScoreItem struct {
	IsBlock      bool
	IsSuspicious bool
	IsDangerous  bool
	Flag         []string
	Score        int
	Detail       map[string]interface{}
	Timestamp    int64
}

type RiskScore struct {
	Base   int
	Detail map[string]interface{}
}

// func (i *IPGuardian) dynamicScore(device *Device) (*ScoreItem, error) {
// 	var list []string
// 	score := RiskScore{
// 		Base:   0,
// 		Detail: make(map[string]interface{}),
// 	}

// 	if err := i.calcBasic(device, &list, &score); err != nil {
// 		return nil, err
// 	}

// 	if err := i.calcGeo(device, &list, &score); err != nil {
// 		return nil, err
// 	}

// 	if err := i.calcBehavior(device, &list, &score); err != nil {
// 		return nil, err
// 	}

// 	if err := i.calcFingerprint(device, &list, &score); err != nil {
// 		return nil, err
// 	}

// 	totalRisk := i.calcScore(score)

// 	if totalRisk > 100 {
// 		i.Manager.Block.Add(device.IP.Address, "Score greater than 100")
// 	}

// 	print(totalRisk)

// 	return &ScoreItem{
// 		IsBlock:      totalRisk >= 100,
// 		IsSuspicious: totalRisk >= i.Config.Parameter.ScoreSuspicious,
// 		IsDangerous:  totalRisk >= i.Config.Parameter.ScoreDangerous,
// 		Flag:         list,
// 		Score:        totalRisk,
// 		Detail:       score.Detail,
// 	}, nil
// }

func (i *IPGuardian) dynamicScore(device *Device) (*ScoreItem, error) {
	var wg sync.WaitGroup
	var mu sync.Mutex

	var combinedFlags []string
	combinedScore := RiskScore{
		Base:   0,
		Detail: make(map[string]interface{}),
	}

	errChan := make(chan error, 4)

	if i.Config.Parameter.ScoreSuspicious <= 0 {
		i.Config.Parameter.ScoreSuspicious = 50
	}
	if i.Config.Parameter.ScoreDangerous <= 0 {
		i.Config.Parameter.ScoreDangerous = 80
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		var localFlags []string
		localScore := RiskScore{
			Base:   0,
			Detail: make(map[string]interface{}),
		}

		if err := i.calcBasic(device, &localFlags, &localScore); err != nil {
			errChan <- err
			return
		}

		mu.Lock()
		combinedFlags = append(combinedFlags, localFlags...)
		combinedScore.Base += localScore.Base
		for k, v := range localScore.Detail {
			combinedScore.Detail[k] = v
		}
		mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		var localFlags []string
		localScore := RiskScore{
			Base:   0,
			Detail: make(map[string]interface{}),
		}

		if err := i.calcGeo(device, &localFlags, &localScore); err != nil {
			errChan <- err
			return
		}

		mu.Lock()
		combinedFlags = append(combinedFlags, localFlags...)
		combinedScore.Base += localScore.Base
		for k, v := range localScore.Detail {
			combinedScore.Detail[k] = v
		}
		mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		var localFlags []string
		localScore := RiskScore{
			Base:   0,
			Detail: make(map[string]interface{}),
		}

		if err := i.calcBehavior(device, &localFlags, &localScore); err != nil {
			errChan <- err
			return
		}

		mu.Lock()
		combinedFlags = append(combinedFlags, localFlags...)
		combinedScore.Base += localScore.Base
		for k, v := range localScore.Detail {
			combinedScore.Detail[k] = v
		}
		mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		var localFlags []string
		localScore := RiskScore{
			Base:   0,
			Detail: make(map[string]interface{}),
		}

		if err := i.calcFingerprint(device, &localFlags, &localScore); err != nil {
			errChan <- err
			return
		}

		mu.Lock()
		combinedFlags = append(combinedFlags, localFlags...)
		combinedScore.Base += localScore.Base
		for k, v := range localScore.Detail {
			combinedScore.Detail[k] = v
		}
		mu.Unlock()
	}()

	wg.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			return nil, err
		}
	}

	totalRisk := i.calcScore(combinedScore)

	if totalRisk > 100 {
		i.Manager.Block.Add(device.IP.Address, "Score greater than 100")
	}

	return &ScoreItem{
		IsBlock:      totalRisk >= 100,
		IsSuspicious: totalRisk >= i.Config.Parameter.ScoreSuspicious,
		IsDangerous:  totalRisk >= i.Config.Parameter.ScoreDangerous,
		Flag:         combinedFlags,
		Score:        totalRisk,
		Detail:       combinedScore.Detail,
	}, nil
}

// 更進階的並行優化 - 使用工作池模式
type ScoreTask struct {
	Name string
	Func func(*Device, *[]string, *RiskScore) error
}

type ScoreResult struct {
	Name  string
	Flags []string
	Score RiskScore
	Error error
}

// func (i *IPGuardian) dynamicScoreAdvanced(device *Device) (*ScoreItem, error) {
// 	// 定義計算任務
// 	tasks := []ScoreTask{
// 		{"basic", i.calcBasic},
// 		{"geo", i.calcGeo},
// 		{"behavior", i.calcBehavior},
// 		{"fingerprint", i.calcFingerprint},
// 	}

// 	// 結果通道
// 	resultChan := make(chan ScoreResult, len(tasks))

// 	// 並行執行所有任務
// 	for _, task := range tasks {
// 		go func(t ScoreTask) {
// 			var flags []string
// 			score := RiskScore{
// 				Base:   0,
// 				Detail: make(map[string]interface{}),
// 			}

// 			err := t.Func(device, &flags, &score)

// 			resultChan <- ScoreResult{
// 				Name:  t.Name,
// 				Flags: flags,
// 				Score: score,
// 				Error: err,
// 			}
// 		}(task)
// 	}

// 	// 收集所有結果
// 	var combinedFlags []string
// 	combinedScore := RiskScore{
// 		Base:   0,
// 		Detail: make(map[string]interface{}),
// 	}

// 	for i := 0; i < len(tasks); i++ {
// 		result := <-resultChan

// 		if result.Error != nil {
// 			return nil, fmt.Errorf("error in %s calculation: %w", result.Name, result.Error)
// 		}

// 		// 合併結果
// 		combinedFlags = append(combinedFlags, result.Flags...)
// 		combinedScore.Base += result.Score.Base
// 		for k, v := range result.Score.Detail {
// 			combinedScore.Detail[k] = v
// 		}
// 	}

// 	close(resultChan)

// 	// 計算最終風險評分
// 	totalRisk := i.calcScore(combinedScore)

// 	if totalRisk > 100 {
// 		i.Manager.Block.Add(device.IP.Address, "Score greater than 100")
// 	}

// 	return &ScoreItem{
// 		IsBlock:      totalRisk >= 100,
// 		IsSuspicious: totalRisk >= i.Config.Parameter.ScoreSuspicious,
// 		IsDangerous:  totalRisk >= i.Config.Parameter.ScoreDangerous,
// 		Flag:         combinedFlags,
// 		Score:        totalRisk,
// 		Detail:       combinedScore.Detail,
// 	}, nil
// }

type BasicItem struct {
	key       string
	value     string
	threshold int
	flagName  string
	riskPoint int
}

func (i *IPGuardian) calcBasic(device *Device, flags *[]string, riskScore *RiskScore) error {
	if err := validateDevice(device); err != nil {
		return err
	}

	if i.Config.Parameter.SessionMultiIP <= 0 {
		i.Config.Parameter.SessionMultiIP = 4
	}

	if i.Config.Parameter.ScoreSessionMultiIP <= 0 {
		i.Config.Parameter.ScoreSessionMultiIP = 25
	}

	if i.Config.Parameter.IPMultiDevice <= 0 {
		i.Config.Parameter.IPMultiDevice = 8
	}
	if i.Config.Parameter.ScoreIPMultiDevice <= 0 {
		i.Config.Parameter.ScoreIPMultiDevice = 20
	}

	if i.Config.Parameter.DeviceMultiIP <= 0 {
		i.Config.Parameter.DeviceMultiIP = 4
	}
	if i.Config.Parameter.ScoreDeviceMultiIP <= 0 {
		i.Config.Parameter.ScoreDeviceMultiIP = 15
	}

	if i.Config.Parameter.LoginFailure <= 0 {
		i.Config.Parameter.LoginFailure = 4
	}
	if i.Config.Parameter.NotFound404 <= 0 {
		i.Config.Parameter.NotFound404 = 8
	}

	if i.Config.Parameter.ScoreLoginFailure <= 0 {
		i.Config.Parameter.ScoreLoginFailure = 15
	}
	if i.Config.Parameter.ScoreNotFound404 <= 0 {
		i.Config.Parameter.ScoreNotFound404 = 15
	}

	operations := []BasicItem{
		{
			key:       fmt.Sprintf(redisSessionIP, device.SessionID),
			value:     device.IP.Address,
			threshold: i.Config.Parameter.SessionMultiIP,
			flagName:  "session_multi_ip",
			riskPoint: i.Config.Parameter.ScoreSessionMultiIP,
		},
		{
			key:       fmt.Sprintf(redisIPDevice, device.IP.Address),
			value:     device.Fingerprint,
			threshold: i.Config.Parameter.IPMultiDevice,
			flagName:  "ip_multi_device",
			riskPoint: i.Config.Parameter.ScoreIPMultiDevice,
		},
		{
			key:       fmt.Sprintf(redisDeviceFp, device.Fingerprint),
			value:     device.IP.Address,
			threshold: i.Config.Parameter.DeviceMultiIP,
			flagName:  "device_multi_ip",
			riskPoint: i.Config.Parameter.ScoreDeviceMultiIP,
		},
	}

	pipe := i.Redis.Pipeline()
	var countCmds []*redis.IntCmd

	for _, op := range operations {
		pipe.SAdd(i.Context, op.key, op.value)
		countCmds = append(countCmds, pipe.SCard(i.Context, op.key))
		pipe.Expire(i.Context, op.key, time.Hour)
	}

	notFound404Key := fmt.Sprintf(redisNotFound404, device.SessionID)
	loginFailureKey := fmt.Sprintf(redisLoginFailure, device.SessionID)

	notFound404Cmd := pipe.Get(i.Context, notFound404Key)
	loginFailureCmd := pipe.Get(i.Context, loginFailureKey)

	if _, err := pipe.Exec(i.Context); err != nil && err.Error() != "redis: nil" {
		return fmt.Errorf("failed to execute redis pipeline: %w", err)
	}

	for i, op := range operations {
		count, err := countCmds[i].Result()
		if err != nil {
			return fmt.Errorf("failed to get count for %s: %w", op.key, err)
		}

		if int(count) > int(math.Floor(float64(op.threshold)*1.5)) {
			*flags = append(*flags, op.flagName)
			riskScore.Base += op.riskPoint * 2
			riskScore.Detail[op.flagName] = count
		} else if int(count) > op.threshold {
			*flags = append(*flags, op.flagName)
			riskScore.Base += op.riskPoint
			riskScore.Detail[op.flagName] = count
		}
	}

	if notFound404Count, err := notFound404Cmd.Result(); err == nil {
		if count, parseErr := strconv.Atoi(notFound404Count); parseErr == nil {
			if count > int(math.Floor(float64(i.Config.Parameter.NotFound404)*1.5)) {
				*flags = append(*flags, "excessive_404_errors")
				riskScore.Base += i.Config.Parameter.ScoreNotFound404 * 2
				riskScore.Detail["notFound404Count"] = count
			} else if count > i.Config.Parameter.NotFound404 {
				*flags = append(*flags, "frequent_404_errors")
				riskScore.Base += i.Config.Parameter.ScoreNotFound404
				riskScore.Detail["notFound404Count"] = count
			}
		}
	}

	if loginFailureCount, err := loginFailureCmd.Result(); err == nil {
		if count, parseErr := strconv.Atoi(loginFailureCount); parseErr == nil {
			if count > int(math.Floor(float64(i.Config.Parameter.LoginFailure)*1.5)) {
				*flags = append(*flags, "excessive_login_failures")
				riskScore.Base += i.Config.Parameter.ScoreLoginFailure * 2
				riskScore.Detail["loginFailureCount"] = count
			} else if count > i.Config.Parameter.LoginFailure {
				*flags = append(*flags, "frequent_login_failures")
				riskScore.Base += i.Config.Parameter.ScoreLoginFailure
				riskScore.Detail["loginFailureCount"] = count
			}
		}
	}

	return nil
}

func (i *IPGuardian) calcGeo(device *Device, flags *[]string, score *RiskScore) error {
	if err := validateDevice(device); err != nil {
		return err
	}

	if i.GeoLite2 == nil || i.GeoLite2.CityDB == nil {
		return nil
	}

	record, err := i.GeoLite2.location(device.IP.Address)
	if err != nil {
		log.Printf("Failed to get geo record for IP %s: %v", device.IP.Address, err)
		return nil
	}

	city := record.City

	location := fmt.Sprintf("%s:%s:%.4f:%.4f", record.CountryCode, city, record.Latitude, record.Longitude)
	geoKey := fmt.Sprintf(redisGeoLocation, device.SessionID)
	locationWithTime := fmt.Sprintf("%d:%s", time.Now().UTC().UnixMilli(), location)

	log.Print(location, geoKey)

	// Redis操作批量處理
	pipe := i.Redis.Pipeline()
	pipe.LPush(i.Context, geoKey, locationWithTime)
	pipe.LTrim(i.Context, geoKey, 0, 9)
	pipe.Expire(i.Context, geoKey, 24*time.Hour)
	_, err = pipe.Exec(i.Context)
	if err != nil {
		return err
	}

	locations, err := i.Redis.LRange(i.Context, geoKey, 0, -1).Result()
	if err != nil {
		return err
	}

	return i.GeoLite2.risk(locations, flags, score)
}

func (i *IPGuardian) calcBehavior(device *Device, flags *[]string, score *RiskScore) error {
	if err := validateDevice(device); err != nil {
		return err
	}

	intervalKey := fmt.Sprintf(redisIntervalLast, device.SessionID)
	sessionStartKey := fmt.Sprintf(redisSessionStart, device.SessionID)

	pipe := i.Redis.Pipeline()
	lastRequestCmd := pipe.Get(i.Context, intervalKey)
	sessionStartCmd := pipe.Get(i.Context, sessionStartKey)
	_, err := pipe.Exec(i.Context)

	lastRequestStr, err1 := lastRequestCmd.Result()
	if err1 == nil && lastRequestStr != "" {
		lastRequest, _ := strconv.ParseInt(lastRequestStr, 10, 64)
		timeDiff := time.Now().UTC().UnixMilli() - lastRequest
		intervalHistoryKey := fmt.Sprintf(redisInterval, device.SessionID)

		pipe2 := i.Redis.Pipeline()
		pipe2.LPush(i.Context, intervalHistoryKey, timeDiff)
		pipe2.LTrim(i.Context, intervalHistoryKey, 0, 9)
		pipe2.Expire(i.Context, intervalHistoryKey, time.Hour)
		intervalsCmd := pipe2.LRange(i.Context, intervalHistoryKey, 0, 9)
		_, err := pipe2.Exec(i.Context)
		if err != nil {
			return err
		}

		intervals, err := intervalsCmd.Result()
		if err != nil {
			return err
		}

		if i.Config.Parameter.ScoreIntervalRequest <= 0 {
			i.Config.Parameter.ScoreIntervalRequest = 25
		}

		if len(intervals) >= 5 {
			var sum int64
			var values []int64
			var tooFastCount int

			for _, interval := range intervals {
				val, _ := strconv.ParseInt(interval, 10, 64)
				values = append(values, val)
				sum += val

				if val < 500 {
					tooFastCount++
				}
			}

			avgInterval := float64(sum) / float64(len(values))
			var variance float64
			for _, val := range values {
				variance += math.Pow(float64(val)-avgInterval, 2)
			}
			variance /= float64(len(values))

			if variance < 1000 && avgInterval > 500 && avgInterval < 30000 {
				*flags = append(*flags, "interval_request")
				score.Base += i.Config.Parameter.ScoreIntervalRequest
				score.Detail["regularInterval"] = map[string]interface{}{
					"avg":      avgInterval,
					"variance": variance,
				}
			}

			if tooFastCount >= 16 {
				*flags = append(*flags, "too_frequent_requests")
				score.Base += i.Config.Parameter.ScoreFrequencyRequest
				score.Detail["tooFrequentRequests"] = map[string]interface{}{
					"count":        tooFastCount,
					"totalChecked": len(values),
				}
			}

			if variance < 100 && len(values) >= 8 {
				*flags = append(*flags, "extremely_regular")
				score.Base += int(float64(i.Config.Parameter.ScoreIntervalRequest) * 1.5)
				score.Detail["extremelyRegular"] = variance
			}
		}
	}

	if i.Config.Parameter.ScoreLongConnection <= 0 {
		i.Config.Parameter.ScoreLongConnection = 15
	}

	sessionStartStr, err2 := sessionStartCmd.Result()

	pipe3 := i.Redis.Pipeline()
	pipe3.SetEx(i.Context, intervalKey, time.Now().UTC().UnixMilli(), time.Hour)

	if err2 == redis.Nil {
		pipe3.SetEx(i.Context, sessionStartKey, time.Now().UTC().UnixMilli(), 15*time.Minute)
	} else if err2 == nil {
		pipe3.Expire(i.Context, sessionStartKey, 15*time.Minute)

		sessionStart, _ := strconv.ParseInt(sessionStartStr, 10, 64)
		duration := time.Now().UTC().UnixMilli() - sessionStart

		if duration > 4*3600*1000 {
			*flags = append(*flags, "extremely_long_connection")
			score.Base += i.Config.Parameter.ScoreLongConnection * 2
			score.Detail["sessionDuration"] = duration
		} else if duration > 2*3600*1000 {
			*flags = append(*flags, "long_connection")
			score.Base += int(float64(i.Config.Parameter.ScoreLongConnection) * 1.5)
			score.Detail["sessionDuration"] = duration
		} else if duration > 1*3600*1000 {
			*flags = append(*flags, "moderate_long_connection")
			score.Base += i.Config.Parameter.ScoreLongConnection
			score.Detail["sessionDuration"] = duration
		}
	}

	_, err = pipe3.Exec(i.Context)
	return err
}

func (i *IPGuardian) calcFingerprint(device *Device, flags *[]string, score *RiskScore) error {
	if err := validateDevice(device); err != nil {
		return err
	}

	if i.Config.Parameter.ScoreFpMultiSession <= 0 {
		i.Config.Parameter.ScoreFpMultiSession = 50
	}

	currentMinute := time.Now().UTC().UnixMilli() / 60000
	fingerprintSessionKey := fmt.Sprintf(redisFpSession, currentMinute, device.Fingerprint)

	if err := i.Redis.SAdd(i.Context, fingerprintSessionKey, device.SessionID).Err(); err != nil {
		return err
	}

	if err := i.Redis.Expire(i.Context, fingerprintSessionKey, time.Minute).Err(); err != nil {
		return err
	}

	sessionCount, err := i.Redis.SCard(i.Context, fingerprintSessionKey).Result()
	if err != nil {
		return err
	}

	if int(sessionCount) > 2 {
		*flags = append(*flags, "fp_multi_session")
		score.Base += i.Config.Parameter.ScoreFpMultiSession
		score.Detail["fingerprintSessions"] = sessionCount
	}

	return nil
}

func (i *IPGuardian) calcScore(score RiskScore) int {
	total := score.Base

	if len(score.Detail) > 4 {
		total += 25
	}

	return int(math.Min(float64(total), 100))
}

func validateDevice(device *Device) error {
	var errors []string

	if device.SessionID == "" {
		errors = append(errors, "sessionID is required")
	}

	if device.IP.Address == "" {
		errors = append(errors, "ip is required")
	} else if net.ParseIP(device.IP.Address) == nil {
		errors = append(errors, "invalid IP format")
	}

	if device.Fingerprint == "" {
		errors = append(errors, "fingerprint is required")
	}

	if len(errors) > 0 {
		return fmt.Errorf("validation failed: %s", strings.Join(errors, ", "))
	}

	return nil
}

func getMapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// * public
func (i *IPGuardian) NotFound404(w http.ResponseWriter, r *http.Request) error {
	device, err := i.getDevice(w, r)
	if err != nil {
		return i.Logger.Error(err, "Failed to get device")
	}

	key := fmt.Sprintf(redisNotFound404, device.SessionID)

	count, err := i.Redis.Incr(i.Context, key).Result()
	if err != nil {
		return i.Logger.Error(err, "Failed to increase 404 count")
	}

	if count == 1 {
		if err := i.Redis.Expire(i.Context, key, time.Hour).Err(); err != nil {
			return i.Logger.Error(err, "Failed to set expiration for 404 count")
		}
	}

	return nil
}

// * public
func (i *IPGuardian) LoginFailure(w http.ResponseWriter, r *http.Request) error {
	device, err := i.getDevice(w, r)
	if err != nil {
		return i.Logger.Error(err, "Failed to get device")
	}

	key := fmt.Sprintf(redisLoginFailure, device.SessionID)

	count, err := i.Redis.Incr(i.Context, key).Result()
	if err != nil {
		return i.Logger.Error(err, "Failed to increase login failure count")
	}

	if count == 1 {
		if err := i.Redis.Expire(i.Context, key, time.Hour).Err(); err != nil {
			return i.Logger.Error(err, "Failed to set expiration for login failure count")
		}
	}

	return nil
}
