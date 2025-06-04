package golangIPGuardian

import (
	"fmt"
	"math"
	"net"
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

	// wg.Add(1)
	// go func() {
	// 	defer wg.Done()
	// 	var localFlags []string
	// 	localScore := RiskScore{
	// 		Base:   0,
	// 		Detail: make(map[string]interface{}),
	// 	}

	// 	if err := i.calcGeo(device, &localFlags, &localScore); err != nil {
	// 		errChan <- err
	// 		return
	// 	}

	// 	mu.Lock()
	// 	combinedFlags = append(combinedFlags, localFlags...)
	// 	combinedScore.Base += localScore.Base
	// 	for k, v := range localScore.Detail {
	// 		combinedScore.Detail[k] = v
	// 	}
	// 	mu.Unlock()
	// }()

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

func (i *IPGuardian) dynamicScoreAdvanced(device *Device) (*ScoreItem, error) {
	// 定義計算任務
	tasks := []ScoreTask{
		{"basic", i.calcBasic},
		// {"geo", i.calcGeo},
		{"behavior", i.calcBehavior},
		{"fingerprint", i.calcFingerprint},
	}

	// 結果通道
	resultChan := make(chan ScoreResult, len(tasks))

	// 並行執行所有任務
	for _, task := range tasks {
		go func(t ScoreTask) {
			var flags []string
			score := RiskScore{
				Base:   0,
				Detail: make(map[string]interface{}),
			}

			err := t.Func(device, &flags, &score)

			resultChan <- ScoreResult{
				Name:  t.Name,
				Flags: flags,
				Score: score,
				Error: err,
			}
		}(task)
	}

	// 收集所有結果
	var combinedFlags []string
	combinedScore := RiskScore{
		Base:   0,
		Detail: make(map[string]interface{}),
	}

	for i := 0; i < len(tasks); i++ {
		result := <-resultChan

		if result.Error != nil {
			return nil, fmt.Errorf("error in %s calculation: %w", result.Name, result.Error)
		}

		// 合併結果
		combinedFlags = append(combinedFlags, result.Flags...)
		combinedScore.Base += result.Score.Base
		for k, v := range result.Score.Detail {
			combinedScore.Detail[k] = v
		}
	}

	close(resultChan)

	// 計算最終風險評分
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
			value:     device.Fingerprint,
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

	if _, err := pipe.Exec(i.Context); err != nil {
		return fmt.Errorf("failed to execute redis pipeline: %w", err)
	}

	for i, op := range operations {
		count, err := countCmds[i].Result()
		if err != nil {
			return fmt.Errorf("failed to get count for %s: %w", op.key, err)
		}

		// * 超過 1.5 倍閾值，標記為高風險
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

	return nil
}

// TODO: Geo 檢查未完成
// func (i *IPGuardian) calcGeo(device *Device, flags *[]string, riskScore *RiskScore) error {
// 	if err := validateDevice(device); err != nil {
// 		return err
// 	}

// 	if i.GeoChecker == nil || i.GeoChecker.DB == nil {
// 		return nil
// 	}

// 	ip := net.ParseIP(device.IP.Address)
// 	if ip == nil {
// 		return nil
// 	}

// 	var location string
// 	record, err := i.GeoChecker.DB.Country(ip)
// 	if err != nil {
// 		log.Printf("Failed to get geo record for IP %s: %v", device.IP.Address, err)
// 		location = "unknown:unknown"
// 		return nil
// 	}

// 	location = fmt.Sprintf("%s:%s", record.Country.IsoCode, record.Country.Names["en"])
// 	geoKey := fmt.Sprintf(redisGeoLocation, device.SessionID)
// 	locationWithTime := fmt.Sprintf("%d:%s", time.Now().UnixMilli(), location)

// 	if err := i.Redis.LPush(i.Context, geoKey, locationWithTime).Err(); err != nil {
// 		return err
// 	}

// 	if err := i.Redis.LTrim(i.Context, geoKey, 0, 9).Err(); err != nil {
// 		return err
// 	}

// 	if err := i.Redis.Expire(i.Context, geoKey, 24*time.Hour).Err(); err != nil {
// 		return err
// 	}

// 	locations, err := i.Redis.LRange(i.Context, geoKey, 0, -1).Result()
// 	if err != nil {
// 		return err
// 	}

// 	oneHourAgo := time.Now().UnixMilli() - 3600000
// 	var recentLocations []struct {
// 		timestamp int64
// 		country   string
// 	}
// 	recentCountries := make(map[string]bool)

// 	for _, loc := range locations {
// 		parts := strings.SplitN(loc, ":", 3)
// 		if len(parts) >= 3 {
// 			timestamp, _ := strconv.ParseInt(parts[0], 10, 64)
// 			if timestamp >= oneHourAgo {
// 				country := parts[1]
// 				recentCountries[country] = true
// 				recentLocations = append(recentLocations, struct {
// 					timestamp int64
// 					country   string
// 				}{timestamp, country})
// 			}
// 		}
// 	}

// 	if len(recentCountries) > 4 {
// 		*flags = append(*flags, "geo_hopping")
// 		riskScore.Base += i.Config.Parameter.ScoreGeoHopping
// 		riskScore.Detail["geoCountries"] = len(recentCountries)
// 		riskScore.Detail["countries"] = getMapKeys(recentCountries)
// 	}

// 	if len(recentCountries) == 2 && len(recentLocations) >= 5 {
// 		switchCount := 0
// 		for i := 1; i < len(recentLocations); i++ {
// 			if recentLocations[i].country != recentLocations[i-1].country {
// 				switchCount++
// 			}
// 		}

// 		if switchCount >= 4 {
// 			*flags = append(*flags, "geo_frequent_switching")
// 			riskScore.Base += i.Config.Parameter.ScoreGeoFrequentSwitch
// 			riskScore.Detail["geoSwitches"] = switchCount
// 			riskScore.Detail["switchCountries"] = getMapKeys(recentCountries)
// 		}
// 	}

// 	if len(locations) >= 2 {
// 		recent := locations[:2]
// 		parts1 := strings.SplitN(recent[0], ":", 3)
// 		parts2 := strings.SplitN(recent[1], ":", 3)

// 		if len(parts1) >= 3 && len(parts2) >= 3 {
// 			timestamp1, _ := strconv.ParseInt(parts1[0], 10, 64)
// 			timestamp2, _ := strconv.ParseInt(parts2[0], 10, 64)
// 			timeDiff := timestamp1 - timestamp2

// 			country1 := parts1[1]
// 			country2 := parts2[1]

// 			// 1小時內跨國
// 			if timeDiff < 3600000 && country1 != country2 {
// 				*flags = append(*flags, "rapid_geo_change")
// 				riskScore.Base += i.Config.Parameter.ScoreGeoRapidChange
// 				riskScore.Detail["rapidGeoChange"] = map[string]interface{}{
// 					"from":   fmt.Sprintf("%s:%s", parts2[1], parts2[2]),
// 					"to":     fmt.Sprintf("%s:%s", parts1[1], parts1[2]),
// 					"timeMs": timeDiff,
// 				}
// 			}
// 		}
// 	}

// 	return nil
// }

func (i *IPGuardian) calcBehavior(device *Device, flags *[]string, riskScore *RiskScore) error {
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
		timeDiff := time.Now().UnixMilli() - lastRequest
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
				riskScore.Base += i.Config.Parameter.ScoreIntervalRequest
				riskScore.Detail["regularInterval"] = map[string]interface{}{
					"avg":      avgInterval,
					"variance": variance,
				}
			}

			if tooFastCount >= 16 {
				*flags = append(*flags, "too_frequent_requests")
				riskScore.Base += i.Config.Parameter.ScoreFrequencyRequest
				riskScore.Detail["tooFrequentRequests"] = map[string]interface{}{
					"count":        tooFastCount,
					"totalChecked": len(values),
				}
			}

			if variance < 100 && len(values) >= 8 {
				*flags = append(*flags, "extremely_regular")
				riskScore.Base += int(float64(i.Config.Parameter.ScoreIntervalRequest) * 1.5)
				riskScore.Detail["extremelyRegular"] = variance
			}
		}
	}

	sessionStartStr, err2 := sessionStartCmd.Result()

	pipe3 := i.Redis.Pipeline()
	pipe3.SetEx(i.Context, intervalKey, time.Now().UnixMilli(), time.Hour)

	if err2 == redis.Nil {
		pipe3.SetEx(i.Context, sessionStartKey, time.Now().UnixMilli(), 15*time.Minute)
	} else if err2 == nil {
		pipe3.Expire(i.Context, sessionStartKey, 15*time.Minute)

		sessionStart, _ := strconv.ParseInt(sessionStartStr, 10, 64)
		duration := time.Now().UnixMilli() - sessionStart

		if duration > 4*3600*1000 {
			*flags = append(*flags, "extremely_long_connection")
			riskScore.Base += i.Config.Parameter.ScoreLongConnection * 2
			riskScore.Detail["sessionDuration"] = duration
		} else if duration > 2*3600*1000 {
			*flags = append(*flags, "long_connection")
			riskScore.Base += int(float64(i.Config.Parameter.ScoreLongConnection) * 1.5)
			riskScore.Detail["sessionDuration"] = duration
		} else if duration > 1*3600*1000 {
			*flags = append(*flags, "moderate_long_connection")
			riskScore.Base += i.Config.Parameter.ScoreLongConnection
			riskScore.Detail["sessionDuration"] = duration
		}
	}

	_, err = pipe3.Exec(i.Context)
	return err
}

func (i *IPGuardian) calcFingerprint(device *Device, flags *[]string, riskScore *RiskScore) error {
	if err := validateDevice(device); err != nil {
		return err
	}

	currentMinute := time.Now().UnixMilli() / 60000
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
		riskScore.Base += i.Config.Parameter.ScoreFpMultiSession
		riskScore.Detail["fingerprintSessions"] = sessionCount
	}

	return nil
}

func (i *IPGuardian) calcScore(riskScore RiskScore) int {
	total := riskScore.Base

	if len(riskScore.Detail) > 4 {
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
