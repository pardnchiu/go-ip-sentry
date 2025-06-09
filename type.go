package golangIPSentry

import (
	"context"
	"sync"
	"time"

	goLogger "github.com/pardnchiu/go-logger"
	"github.com/redis/go-redis/v9"
)

type Log = goLogger.Log
type Logger = goLogger.Logger

const (
	sessionKey = "conn.sess.id"
	deviceKey  = "conn.device.id"
)

const (
	redisSessionIP    = "session:ip:%s"
	redisIPDevice     = "ip:device:%s"
	redisDeviceFp     = "device:fp:%s"
	redisGeoIP        = "geo:ip:%s"
	redisGeoLocation  = "geo:locations:%s"
	redisIntervalLast = "interval:last:%s"
	redisSessionStart = "session:start:%s"
	redisFpSession    = "fp:session:%d:%s"
	redisInterval     = "interval:%s"
	redisSuspicious   = "suspicious:%d:%s"
	redisAllow        = "allow:%s"
	redisDeny         = "deny:%s"
	redisBlock        = "block:%s"
	redisBlockCount   = "block:count:%s"
	redisFrequency    = "frequency:%s:%d"
	redisLoginFailure = "login:failure:%s"
	redisNotFound404  = "notfound:404:%s"
)

const (
	defaultLogPath       = "./logs/mysqlPool"
	defaultLogMaxSize    = 16 * 1024 * 1024
	defaultLogMaxBackup  = 5
	defaultWhiteListPath = "./whiteList.json"
	defaultBlackListPath = "./blackList.json"
)

var (
	sessionSecret string
	secretOnce    sync.Once
)

var internalIPs = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"::1/128",
	"fc00::/7",
}

type Config struct {
	Redis     Redis        `json:"redis"`
	Email     *EmailConfig `json:"email"`
	Log       *Log         `json:"log"`
	Filepath  Filepath     `json:"filepath"`
	Parameter Parameter    `json:"parameter"`
	// AbuseIPDBToken  string       `json:"abuseipdb_token"`
	// AbuseIPDBIsPaid bool         `json:"abuseipdb_is_paid"`
}

type Filepath struct {
	CityDB    string `json:"city_db"`
	CountryDB string `json:"country_db"`
	WhiteList string `json:"trust_list"`
	BlackList string `json:"ban_list"`
}

type EmailConfig struct {
	Host     string                                 `json:"host"`
	Port     int                                    `json:"port"`
	Username string                                 `json:"username"`
	Password string                                 `json:"password"`
	From     string                                 `json:"from"`
	To       []string                               `json:"to"`
	CC       []string                               `json:"cc"`
	Subject  *func(ip string, reason string) string `json:"-"` // default: "[IP Sentry] IP {ip} has been banned"
	Body     *func(ip string, reason string) string `json:"-"` // default: "[IP Sentry] IP {ip} has been banned for {reason}"
}

type Parameter struct {
	HighRiskCountry        []string      `json:"high_risk_country"`         // 高風險國家列表
	BlockToBan             int           `json:"block_to_ban"`              // 封鎖到禁止的次數
	BlockTimeMin           time.Duration `json:"block_time_min"`            // 最小封鎖時間
	BlockTimeMax           time.Duration `json:"block_time_max"`            // 最大限制時間
	RateLimitNormal        int           `json:"rate_limit_normal"`         // 正常請求速率限制
	RateLimitSuspicious    int           `json:"rate_limit_suspicious"`     // 可疑請求速率限制
	RateLimitDangerous     int           `json:"rate_limit_dangerous"`      // 危險請求速率限制
	SessionMultiIP         int           `json:"session_multi_ip"`          // 單一 Session 允許的最大 IP 數
	IPMultiDevice          int           `json:"ip_multi_device"`           // 單一 IP 允許的最大設備數
	DeviceMultiIP          int           `json:"device_multi_ip"`           // 單一設備允許的最大 IP 數
	LoginFailure           int           `json:"login_failure"`             // 單一 Session 允許的最大登入失敗次數
	NotFound404            int           `json:"not_found_404"`             // 單一 Session 允許的最大 404 請求數
	ScoreNormal            int           `json:"score_normal"`              // 正常請求的風險分數
	ScoreSuspicious        int           `json:"score_suspicious"`          // 可疑請求的風險分數
	ScoreDangerous         int           `json:"score_dangerous"`           // 危險請求的風險分數
	ScoreSessionMultiIP    int           `json:"score_session_multi_ip"`    // 單一 Session 允許的最大 IP 數可疑分數
	ScoreIPMultiDevice     int           `json:"score_ip_multi_device"`     // 單一 IP 允許的最大設備數可疑分數
	ScoreDeviceMultiIP     int           `json:"score_device_multi_ip"`     // 單一設備允許的最大 IP 數可疑分數
	ScoreFpMultiSession    int           `json:"score_fp_multi_session"`    // 單一指紋允許的最大 Session 數可疑分數
	ScoreGeoHighRisk       int           `json:"score_geo_high_risk"`       // 高風險地理位置可疑分數
	ScoreGeoHopping        int           `json:"score_geo_hopping"`         // 地理位置跳躍可疑分數
	ScoreGeoFrequentSwitch int           `json:"score_geo_frequent_switch"` // 地理位置頻繁切換可疑分數
	ScoreGeoRapidChange    int           `json:"score_geo_rapid_change"`    // 地理位置快速變化可疑分數
	ScoreIntervalRequest   int           `json:"score_interval_request"`    // 短時間內的請求數可疑分數
	ScoreFrequencyRequest  int           `json:"score_frequency_request"`   // 請求頻率可疑分數
	ScoreLongConnection    int           `json:"score_long_connection"`     // 長連接可疑分數
	ScoreLoginFailure      int           `json:"score_login_failure"`       // 登入失敗可疑分數
	ScoreNotFound404       int           `json:"score_not_found_404"`       // 404 請求可疑分數
}

type IPGuardian struct {
	Context  context.Context
	Config   *Config
	Redis    *redis.Client
	Logger   *Logger
	GeoLite2 *GeoLite2
	Manager  *Manager
	// AbuseIPDBApi *AbuseIPDBApi
}

type Manager struct {
	Allow *AllowIPManager
	Block *BlockIPManager
	Deny  *DenyIPManager
}

type Redis struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	DB       int    `json:"db"`
}

type IPItem struct {
	IP      string `json:"ip"`
	Reason  string `json:"reason"`
	AddedAt int64  `json:"added_at"`
	Count   int    `json:"count,omitempty"`
	Last    int64  `json:"last,omitempty"`
}

// type AbuseIPDBApi struct {
// 	Context context.Context
// 	IsPaid  bool
// 	Token   string
// 	Redis   *redis.Client
// 	HTTP    *http.Client
// 	Logger  *Logger
// 	Last    time.Time
// 	Mutex   sync.Mutex
// }
