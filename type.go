package golangIPGuardian

import (
	"context"
	"sync"

	"github.com/redis/go-redis/v9"
)

const (
	sessionKey        = "conn.sess.id"
	deviceKey         = "conn.device.id"
	redisSessionIP    = "session:ip:%s"
	redisIPDevice     = "ip:device:%s"
	redisDeviceFp     = "device:fp:%s"
	redisGeoLocation  = "geo:locations:%s"
	redisIntervalLast = "interval:last:%s"
	redisSessionStart = "session:start:%s"
	redisFpSession    = "fp:session:%d:%s"
	redisInterval     = "interval:%s"
	redisSuspicious   = "suspicious:%d:%s"
	redisTrust        = "trust:%s"
	redisBan          = "ban:%s"
	redisBlock        = "block:%s"
	redisBlockCount   = "block:count:%s"
	redisFrequency    = "frequency:%s:%d"
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
	Log       LogConfig    `json:"log"`
	Parameter Parameter    `json:"parameter"`
	// AbuseIPDBToken  string       `json:"abuseipdb_token"`
	// AbuseIPDBIsPaid bool         `json:"abuseipdb_is_paid"`
}

type EmailConfig struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	From     string   `json:"from"`
	To       []string `json:"to"`
}

type Parameter struct {
	BlockToBan             int `json:"block_to_ban"`              // 封鎖到禁止的次數
	BlockTimeMin           int `json:"block_time_min"`            // 最小封鎖時間（秒）
	BlockTimeMax           int `json:"block_time_max"`            // 最大限制時間（秒）
	RateLimitNormal        int `json:"rate_limit_normal"`         // 正常請求速率限制
	RateLimitSuspicious    int `json:"rate_limit_suspicious"`     // 可疑請求速率限制
	RateLimitDangerous     int `json:"rate_limit_dangerous"`      // 危險請求速率限制
	SessionMultiIP         int `json:"session_multi_ip"`          // 單一 Session 允許的最大 IP 數
	IPMultiDevice          int `json:"ip_multi_device"`           // 單一 IP 允許的最大設備數
	DeviceMultiIP          int `json:"device_multi_ip"`           // 單一設備允許的最大 IP 數
	LoginFailure           int `json:"login_failure"`             // 單一 Session 允許的最大登入失敗次數
	NotFound404            int `json:"not_found_404"`             // 單一 Session 允許的最大 404 請求數
	ScoreNormal            int `json:"score_normal"`              // 正常請求的風險分數
	ScoreSuspicious        int `json:"score_suspicious"`          // 可疑請求的風險分數
	ScoreDangerous         int `json:"score_dangerous"`           // 危險請求的風險分數
	ScoreSessionMultiIP    int `json:"score_session_multi_ip"`    // 單一 Session 允許的最大 IP 數可疑分數
	ScoreIPMultiDevice     int `json:"score_ip_multi_device"`     // 單一 IP 允許的最大設備數可疑分數
	ScoreDeviceMultiIP     int `json:"score_device_multi_ip"`     // 單一設備允許的最大 IP 數可疑分數
	ScoreFpMultiSession    int `json:"score_fp_multi_session"`    // 單一指紋允許的最大 Session 數可疑分數
	ScoreGeoHopping        int `json:"score_geo_hopping"`         // 地理位置跳躍可疑分數
	ScoreGeoFrequentSwitch int `json:"score_geo_frequent_switch"` // 地理位置頻繁切換可疑分數
	ScoreGeoRapidChange    int `json:"score_geo_rapid_change"`    // 地理位置快速變化可疑分數
	ScoreIntervalRequest   int `json:"score_interval_request"`    // 短時間內的請求數可疑分數
	ScoreFrequencyRequest  int `json:"score_frequency_request"`   // 請求頻率可疑分數
	ScoreLongConnection    int `json:"score_long_connection"`     // 長連接可疑分數
}

type IPGuardian struct {
	Context context.Context
	Config  *Config
	Redis   *redis.Client
	Logger  *Logger
	// GeoChecker   *GeoCheck
	// AbuseIPDBApi *AbuseIPDBApi
	Manager *Manager
}

type Manager struct {
	Trust *TrustManager
	Ban   *BanManager
	Block *BlockManager
}

// type GeoCheck struct {
// 	DB                *geoip2.Reader
// 	highRiskCountries map[string]bool
// 	proxyRanges       []string // 代理 IP 範圍
// 	vpnRanges         []string // VPN IP 範圍
// }

// type GeoRisk struct {
// 	HighRiskCountries []string `json:"high_risk_countries"`
// 	ProxyDetection    bool     `json:"proxy_detection"`
// 	VPNDetection      bool     `json:"vpn_detection"`
// }

type Redis struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	DB       int    `json:"db"`
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
