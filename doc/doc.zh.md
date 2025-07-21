# go-ip-sentry - 技術文件

最後更新：2026-10-06

> 返回 [README](./README.zh.md)

## 前置需求

- Go 1.24.3 或以上
- Redis（所有計數、名單與地理快取皆存放於 Redis）
- GeoLite2 資料庫（選用，啟用地理異常偵測時需要）
  - `GeoLite2-City.mmdb`：提供城市與經緯度，地理偵測主要依賴此檔
  - `GeoLite2-Country.mmdb`：僅提供國家，作為 City 查詢失敗時的回退
- HTTPS：Session 與指紋 Cookie 皆設為 `Secure` + `SameSite=Strict`，瀏覽器在純 HTTP 下不會回傳，導致每次請求都被視為新 Session

## 安裝

### 使用 go get

```bash
go get github.com/pardnchiu/golang-ip-sentry
```

### 從原始碼

```bash
git clone https://github.com/pardnchiu/go-ip-sentry.git
cd go-ip-sentry
go build ./...
```

> 模組路徑為 `github.com/pardnchiu/golang-ip-sentry`，套件名稱為 `golangIPSentry`，import 時建議明確指定別名。

## 設定

所有設定透過 `golangIPSentry.Config` 傳入 `New()`；未設定或 `<= 0` 的數值欄位會在執行期套用預設值。

### Config

| 欄位 | JSON key | 型別 | 必要 | 說明 |
|------|----------|------|------|------|
| `Redis` | `redis` | `Redis` | 是 | Redis 連線設定 |
| `Email` | `email` | `*EmailConfig` | 否 | Deny 時的 Email 通知，`nil` 則不寄送 |
| `Log` | `log` | `*Log` | 否 | Logger 設定（`pardnchiu/go-logger`） |
| `Filepath` | `filepath` | `Filepath` | 否 | GeoLite2 與名單檔路徑 |
| `Parameter` | `parameter` | `Parameter` | 否 | 評分、門檻與速率限制參數 |

### Redis

| 欄位 | JSON key | 預設值 | 說明 |
|------|----------|--------|------|
| `Host` | `host` | `localhost` | Redis 主機 |
| `Port` | `port` | `6379` | Redis 連接埠（超出 1–65535 時套用預設） |
| `Password` | `password` | `""` | Redis 密碼 |
| `DB` | `db` | `0` | Redis DB 編號 |

`New()` 會先 `PING` Redis，失敗即回傳錯誤。

### Log

| 欄位 | 預設值 | 說明 |
|------|--------|------|
| `Path` | `./logs/mysqlPool` | 日誌路徑 |
| `MaxSize` | `16 MiB` | 單檔大小上限 |
| `MaxBackup` | `5` | 保留的備份數 |
| `Stdout` | `false` | 是否同時輸出到 stdout |

### Filepath

| 欄位 | JSON key | 預設值 | 說明 |
|------|----------|--------|------|
| `CityDB` | `city_db` | `""` | `GeoLite2-City.mmdb` 路徑 |
| `CountryDB` | `country_db` | `""` | `GeoLite2-Country.mmdb` 路徑 |
| `WhiteList` | `trust_list` | `./whiteList.json` | Allow 名單檔 |
| `BlackList` | `ban_list` | `./blackList.json` | Deny 名單檔 |

`CityDB` 與 `CountryDB` 皆空、或兩者皆開啟失敗時，地理偵測整段略過。

### Parameter

#### 速率限制（每 IP 每分鐘請求數）

| 欄位 | JSON key | 預設值 | 套用條件 |
|------|----------|--------|----------|
| `RateLimitNormal` | `rate_limit_normal` | `100` | 所有請求 |
| `RateLimitSuspicious` | `rate_limit_suspicious` | `50` | 分數 ≥ `ScoreSuspicious` |
| `RateLimitDangerous` | `rate_limit_dangerous` | `20` | 分數 ≥ `ScoreDangerous` |

#### 分數門檻

| 欄位 | JSON key | 預設值 | 說明 |
|------|----------|--------|------|
| `ScoreSuspicious` | `score_suspicious` | `50` | 可疑門檻 |
| `ScoreDangerous` | `score_dangerous` | `80` | 危險門檻 |
| `ScoreNormal` | `score_normal` | - | 目前評分流程未使用 |

分數 ≥ `100` 時該次請求直接回 `403`。

#### 關聯門檻（1 小時滑動視窗）

計數超過門檻加 1 倍分數；超過 `floor(門檻 × 1.5)` 加 2 倍分數。

| 門檻欄位 | 預設 | 分數欄位 | 預設 | 計數對象 |
|----------|------|----------|------|----------|
| `SessionMultiIP` | `4` | `ScoreSessionMultiIP` | `25` | 單一 Session 出現的 IP 數 |
| `IPMultiDevice` | `8` | `ScoreIPMultiDevice` | `20` | 單一 IP 出現的裝置指紋數 |
| `DeviceMultiIP` | `4` | `ScoreDeviceMultiIP` | `15` | 單一裝置指紋出現的 IP 數 |
| `LoginFailure` | `4` | `ScoreLoginFailure` | `15` | 經 `LoginFailure()` 回報的次數 |
| `NotFound404` | `8` | `ScoreNotFound404` | `15` | 經 `NotFound404()` 回報的次數 |

#### 行為與指紋分數

| 欄位 | 預設 | 觸發條件 |
|------|------|----------|
| `ScoreFpMultiSession` | `50` | 同一分鐘內同一指紋出現超過 2 個 Session |
| `ScoreIntervalRequest` | `25` | 最近 ≥ 5 次間隔變異數 < 1000 且平均介於 0.5–30 秒；變異數 < 100 且樣本 ≥ 8 再加 1.5 倍 |
| `ScoreFrequencyRequest` | `0` | 需 ≥ 16 次間隔 < 500ms，但僅保留最近 10 筆，現行實作中不會觸發 |
| `ScoreLongConnection` | `15` | Session 持續 > 1 小時（1 倍）、> 2 小時（1.5 倍）、> 4 小時（2 倍）；閒置 15 分鐘重新計時 |

#### 地理分數

| 欄位 | 預設 | 觸發條件 |
|------|------|----------|
| `ScoreGeoHighRisk` | `30` | 來源國家碼位於 `HighRiskCountry` |
| `ScoreGeoHopping` | `15` | 1 小時內出現超過 4 個國家 |
| `ScoreGeoFrequentSwitch` | `20` | 1 小時內 ≥ 4 個城市、≥ 5 筆紀錄且切換超過 4 次 |
| `ScoreGeoRapidChange` | `25` | 相鄰兩筆推算時速 > 800 km/h，或 30 分鐘內移動 > 500 km |

觸發的偵測項目超過 4 個時額外加 `25` 分，總分上限 `100`。

#### 封鎖

| 欄位 | JSON key | 預設值 | 說明 |
|------|----------|--------|------|
| `BlockTimeMin` | `block_time_min` | - | 首次 Block 時長；**必須設定**，`0` 會使 Redis key 無過期時間 |
| `BlockTimeMax` | `block_time_max` | - | Block 時長上限；重複 Block 時長為 `2^count × BlockTimeMin` |
| `BlockToBan` | `block_to_ban` | `8` | Block 期間持續請求的次數上限 |
| `HighRiskCountry` | `high_risk_country` | `[]` | 高風險國家碼（ISO 3166-1 alpha-2） |

`time.Duration` 以 JSON 載入時單位為奈秒。

### EmailConfig

| 欄位 | 型別 | 說明 |
|------|------|------|
| `Host` | `string` | SMTP 主機 |
| `Port` | `int` | SMTP 連接埠 |
| `Username` | `string` | SMTP 帳號（PLAIN Auth） |
| `Password` | `string` | SMTP 密碼 |
| `From` | `string` | 寄件者 |
| `To` | `[]string` | 收件者 |
| `CC` | `[]string` | 副本（僅寫入標頭） |
| `Subject` | `*func(ip, reason string) string` | 自訂主旨，預設 `[IP Sentry] IP {ip} has been banned` |
| `Body` | `*func(ip, reason string) string` | 自訂內文，預設 `[IP Sentry] IP {ip} has been banned for {reason}` |

### 執行期產生的檔案

| 檔案 | 說明 |
|------|------|
| `.sessionSecret` | 工作目錄下的 Session 簽章金鑰（權限 `0600`），不存在時自動產生；刪除會使所有既有 Session 失效 |
| `./whiteList.json` | Allow 名單，`Allow.Add()` 時覆寫 |
| `./blackList.json` | Deny 名單，`Deny.Add()` 時覆寫 |

名單檔格式：

```json
[
  {
    "ip": "203.0.113.10",
    "reason": "office gateway",
    "added_at": 1735689600
  }
]
```

## 使用方式

### 基礎：net/http

```go
package main

import (
	"log"
	"net/http"
	"time"

	golangIPSentry "github.com/pardnchiu/golang-ip-sentry"
)

func main() {
	sentry, err := golangIPSentry.New(golangIPSentry.Config{
		Redis: golangIPSentry.Redis{
			Host: "localhost",
			Port: 6379,
		},
		Parameter: golangIPSentry.Parameter{
			BlockTimeMin: 5 * time.Minute,
			BlockTimeMax: 24 * time.Hour,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer sentry.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	// 每個請求先經過 Check，失敗時回傳 JSON {"error": "..."}
	log.Fatal(http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", sentry.HTTPMiddleware(mux)))
}
```

### Gin 搭配 GeoLite2

```go
package main

import (
	"log"
	"time"

	"github.com/gin-gonic/gin"
	golangIPSentry "github.com/pardnchiu/golang-ip-sentry"
)

func main() {
	sentry, err := golangIPSentry.New(golangIPSentry.Config{
		Redis: golangIPSentry.Redis{
			Host:     "localhost",
			Port:     6379,
			Password: "secret",
		},
		Filepath: golangIPSentry.Filepath{
			CityDB:    "./GeoLite2-City.mmdb",
			CountryDB: "./GeoLite2-Country.mmdb",
		},
		Parameter: golangIPSentry.Parameter{
			BlockTimeMin:    5 * time.Minute,
			BlockTimeMax:    24 * time.Hour,
			ScoreSuspicious: 40,
			ScoreDangerous:  70,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer sentry.Close()

	r := gin.Default()
	r.Use(sentry.GinMiddleware())

	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	if err := r.RunTLS(":8443", "cert.pem", "key.pem"); err != nil {
		log.Fatal(err)
	}
}
```

### 回報登入失敗與 404

`LoginFailure()` 與 `NotFound404()` 以當前 Session 累計次數（1 小時過期），計入下一次評分。

```go
func loginHandler(sentry *golangIPSentry.IPGuardian) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validCredential(r) {
			if err := sentry.LoginFailure(w, r); err != nil {
				log.Printf("report login failure: %v", err)
			}
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Write([]byte("welcome"))
	}
}

func notFoundHandler(sentry *golangIPSentry.IPGuardian) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := sentry.NotFound404(w, r); err != nil {
			log.Printf("report 404: %v", err)
		}
		http.NotFound(w, r)
	}
}
```

### 手動管理名單

```go
// 加入 Allow 名單：後續請求跳過所有檢查
if err := sentry.Manager.Allow.Add("203.0.113.10", "office gateway"); err != nil {
	log.Printf("allow: %v", err)
}

// 加入 Deny 名單：永久拒絕，有設定 Email 時非同步寄送通知
if err := sentry.Manager.Deny.Add("198.51.100.7", "credential stuffing"); err != nil {
	log.Printf("deny: %v", err)
}

// 暫時 Block：重複呼叫時長以 2^count 倍增，上限 BlockTimeMax
if err := sentry.Manager.Block.Add("192.0.2.33", "manual review"); err != nil {
	log.Printf("block: %v", err)
}

allowed := sentry.Manager.Allow.Check("203.0.113.10")
denied := sentry.Manager.Deny.Check("198.51.100.7")
blocked := sentry.Manager.Block.IsBlock("192.0.2.33")
log.Println(allowed, denied, blocked)
```

### 不經中介層直接呼叫 Check

```go
func handler(sentry *golangIPSentry.IPGuardian) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := sentry.Check(r, w)
		if !result.Success {
			http.Error(w, result.Error, result.StatusCode)
			return
		}
		w.Write([]byte("OK"))
	}
}
```

## API 參考

### 建立與釋放

| 函式 | 簽章 | 說明 |
|------|------|------|
| `New` | `func New(c Config) (*IPGuardian, error)` | 套用 Log／Redis 預設值、連線並 `PING` Redis、載入 Allow／Deny 名單檔、開啟 GeoLite2 |
| `Close` | `func (i *IPGuardian) Close() error` | 關閉 Redis、GeoLite2 與 Logger |

### 檢查與中介層

| 函式 | 簽章 | 說明 |
|------|------|------|
| `Check` | `func (i *IPGuardian) Check(r *http.Request, w http.ResponseWriter) IPGuardianResult` | Allow 放行 → Block／Deny 拒絕 → 四維評分 → 分級速率限制；會寫入 Session 與指紋 Cookie |
| `HTTPMiddleware` | `func (i *IPGuardian) HTTPMiddleware(next http.Handler) http.Handler` | `net/http` 中介層，失敗回 JSON `{"error": "..."}` |
| `GinMiddleware` | `func (i *IPGuardian) GinMiddleware() gin.HandlerFunc` | Gin 中介層，失敗時 `c.Abort()` |
| `LoginFailure` | `func (i *IPGuardian) LoginFailure(w http.ResponseWriter, r *http.Request) error` | 累計當前 Session 登入失敗次數 |
| `NotFound404` | `func (i *IPGuardian) NotFound404(w http.ResponseWriter, r *http.Request) error` | 累計當前 Session 404 次數 |

### IPGuardianResult

```go
type IPGuardianResult struct {
	Success    bool   `json:"success"`
	StatusCode int    `json:"status_code"`
	Error      string `json:"error"`
}
```

| StatusCode | 情境 |
|------------|------|
| `200` | 通過 |
| `403` | 位於 Block／Deny、分數 ≥ 100，或超過對應分級的速率限制 |
| `500` | 無法解析用戶端 IP 或產生 Session |

### 名單管理（`IPGuardian.Manager`）

| 方法 | 簽章 | 說明 |
|------|------|------|
| `Allow.Add` | `func (m *AllowIPManager) Add(ip string, tag string) error` | 寫入記憶體、Redis（無過期）與名單檔 |
| `Allow.Check` | `func (m *AllowIPManager) Check(ip string) bool` | 先查 Redis，失敗回退記憶體快取 |
| `Deny.Add` | `func (m *DenyIPManager) Add(ip, reason string) error` | 寫入記憶體、Redis（無過期）與名單檔，並非同步寄送 Email |
| `Deny.Check` | `func (m *DenyIPManager) Check(ip string) bool` | 先查 Redis，失敗回退記憶體快取 |
| `Block.Add` | `func (m *BlockIPManager) Add(ip string, reason string) error` | 暫時封鎖；已在封鎖中則累加次數、串接原因並延長時長 |
| `Block.IsBlock` | `func (m *BlockIPManager) IsBlock(ip string) bool` | 是否處於封鎖期 |

### 用戶端 IP 解析順序

依序讀取以下標頭的第一個合法 IP，皆無則使用 `RemoteAddr`：

`CF-Connecting-IP` → `X-Forwarded-For` → `X-Real-IP` → `X-Client-IP` → `X-Cluster-Client-IP` → `X-Forwarded` → `Forwarded-For` → `Forwarded`

這些標頭可由用戶端偽造，部署時應由前端代理覆寫或清除。

### Redis Key

| Key | TTL | 用途 |
|-----|-----|------|
| `allow:{ip}` / `deny:{ip}` | 無 | 名單 |
| `block:{ip}` | Block 時長 | 暫時封鎖 |
| `frequency:{ip}:{minute}` | 2 分鐘 | 每分鐘請求計數 |
| `session:ip:{sid}` / `ip:device:{ip}` / `device:fp:{fp}` | 1 小時 | 關聯集合 |
| `fp:session:{minute}:{fp}` | 1 分鐘 | 指紋 Session 集合 |
| `geo:ip:{ip}` | 24 小時 | GeoLite2 查詢快取 |
| `geo:locations:{sid}` | 24 小時 | 最近 10 筆位置 |
| `interval:{sid}` / `interval:last:{sid}` | 1 小時 | 請求間隔 |
| `session:start:{sid}` | 15 分鐘（滑動） | Session 起始時間 |
| `login:failure:{sid}` / `notfound:404:{sid}` | 1 小時 | 回報計數 |

***

©️ 2025 [邱敬幃 Pardn Chiu](https://www.linkedin.com/in/pardnchiu)
