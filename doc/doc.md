# go-ip-sentry - Documentation

Last updated: 2026-10-06

> Back to [README](../README.md)

## Prerequisites

- Go 1.24.3 or higher
- Redis (all counters, lists, and geo cache live in Redis)
- GeoLite2 databases (optional, required for geo anomaly detection)
  - `GeoLite2-City.mmdb`: provides city and coordinates; geo detection relies mainly on this file
  - `GeoLite2-Country.mmdb`: country only, used as a fallback when the City lookup fails
- HTTPS: the session and fingerprint cookies are `Secure` + `SameSite=Strict`, so browsers do not send them back over plain HTTP and every request is treated as a new session

## Installation

### Using go get

```bash
go get github.com/pardnchiu/golang-ip-sentry
```

### From Source

```bash
git clone https://github.com/pardnchiu/go-ip-sentry.git
cd go-ip-sentry
go build ./...
```

> The module path is `github.com/pardnchiu/golang-ip-sentry` and the package name is `golangIPSentry`; import it with an explicit alias.

## Configuration

Pass all settings to `New()` through `golangIPSentry.Config`; numeric fields left unset or `<= 0` receive defaults at runtime.

### Config

| Field | JSON key | Type | Required | Description |
|-------|----------|------|----------|-------------|
| `Redis` | `redis` | `Redis` | Yes | Redis connection settings |
| `Email` | `email` | `*EmailConfig` | No | Email notification on Deny; `nil` disables it |
| `Log` | `log` | `*Log` | No | Logger settings (`pardnchiu/go-logger`) |
| `Filepath` | `filepath` | `Filepath` | No | GeoLite2 and list file paths |
| `Parameter` | `parameter` | `Parameter` | No | Scoring, threshold, and rate limit parameters |

### Redis

| Field | JSON key | Default | Description |
|-------|----------|---------|-------------|
| `Host` | `host` | `localhost` | Redis host |
| `Port` | `port` | `6379` | Redis port (default applies outside 1–65535) |
| `Password` | `password` | `""` | Redis password |
| `DB` | `db` | `0` | Redis DB index |

`New()` sends `PING` to Redis first and returns an error on failure.

### Log

| Field | Default | Description |
|-------|---------|-------------|
| `Path` | `./logs/mysqlPool` | Log path |
| `MaxSize` | `16 MiB` | Max size per file |
| `MaxBackup` | `5` | Number of backups kept |
| `Stdout` | `false` | Also write to stdout |

### Filepath

| Field | JSON key | Default | Description |
|-------|----------|---------|-------------|
| `CityDB` | `city_db` | `""` | `GeoLite2-City.mmdb` path |
| `CountryDB` | `country_db` | `""` | `GeoLite2-Country.mmdb` path |
| `WhiteList` | `trust_list` | `./whiteList.json` | Allow list file |
| `BlackList` | `ban_list` | `./blackList.json` | Deny list file |

When both `CityDB` and `CountryDB` are empty, or both fail to open, geo detection is skipped entirely.

### Parameter

#### Rate Limits (requests per IP per minute)

| Field | JSON key | Default | Applies when |
|-------|----------|---------|--------------|
| `RateLimitNormal` | `rate_limit_normal` | `100` | Every request |
| `RateLimitSuspicious` | `rate_limit_suspicious` | `50` | Score ≥ `ScoreSuspicious` |
| `RateLimitDangerous` | `rate_limit_dangerous` | `20` | Score ≥ `ScoreDangerous` |

#### Score Thresholds

| Field | JSON key | Default | Description |
|-------|----------|---------|-------------|
| `ScoreSuspicious` | `score_suspicious` | `50` | Suspicious threshold |
| `ScoreDangerous` | `score_dangerous` | `80` | Dangerous threshold |
| `ScoreNormal` | `score_normal` | - | Not used by the current scoring flow |

A score of `100` or more rejects the request with `403`.

#### Correlation Thresholds (1-hour sliding window)

A count above the threshold adds 1× the score; a count above `floor(threshold × 1.5)` adds 2×.

| Threshold field | Default | Score field | Default | Counts |
|-----------------|---------|-------------|---------|--------|
| `SessionMultiIP` | `4` | `ScoreSessionMultiIP` | `25` | IPs seen by one session |
| `IPMultiDevice` | `8` | `ScoreIPMultiDevice` | `20` | Device fingerprints seen by one IP |
| `DeviceMultiIP` | `4` | `ScoreDeviceMultiIP` | `15` | IPs seen by one device fingerprint |
| `LoginFailure` | `4` | `ScoreLoginFailure` | `15` | Reports via `LoginFailure()` |
| `NotFound404` | `8` | `ScoreNotFound404` | `15` | Reports via `NotFound404()` |

#### Behavior and Fingerprint Scores

| Field | Default | Trigger |
|-------|---------|---------|
| `ScoreFpMultiSession` | `50` | More than 2 sessions share one fingerprint within the same minute |
| `ScoreIntervalRequest` | `25` | Last ≥ 5 intervals have variance < 1000 and an average between 0.5–30 s; variance < 100 with ≥ 8 samples adds another 1.5× |
| `ScoreFrequencyRequest` | `0` | Requires ≥ 16 intervals below 500 ms, but only the last 10 are kept, so it never fires in the current implementation |
| `ScoreLongConnection` | `15` | Session lasts > 1 h (1×), > 2 h (1.5×), > 4 h (2×); 15 minutes of idle time resets the clock |

#### Geo Scores

| Field | Default | Trigger |
|-------|---------|---------|
| `ScoreGeoHighRisk` | `30` | Source country code is in `HighRiskCountry` |
| `ScoreGeoHopping` | `15` | More than 4 countries within 1 hour |
| `ScoreGeoFrequentSwitch` | `20` | ≥ 4 cities, ≥ 5 records, and more than 4 switches within 1 hour |
| `ScoreGeoRapidChange` | `25` | Implied speed between the two latest records > 800 km/h, or > 500 km within 30 minutes |

When more than 4 detections fire, the engine adds an extra `25`; the total caps at `100`.

#### Blocking

| Field | JSON key | Default | Description |
|-------|----------|---------|-------------|
| `BlockTimeMin` | `block_time_min` | - | First block duration; **must be set**, since `0` leaves the Redis key without expiry |
| `BlockTimeMax` | `block_time_max` | - | Block duration cap; repeated blocks last `2^count × BlockTimeMin` |
| `BlockToBan` | `block_to_ban` | `8` | Max requests tolerated while blocked |
| `HighRiskCountry` | `high_risk_country` | `[]` | High-risk country codes (ISO 3166-1 alpha-2) |

`time.Duration` values loaded from JSON are in nanoseconds.

### EmailConfig

| Field | Type | Description |
|-------|------|-------------|
| `Host` | `string` | SMTP host |
| `Port` | `int` | SMTP port |
| `Username` | `string` | SMTP username (PLAIN auth) |
| `Password` | `string` | SMTP password |
| `From` | `string` | Sender |
| `To` | `[]string` | Recipients |
| `CC` | `[]string` | CC (header only) |
| `Subject` | `*func(ip, reason string) string` | Custom subject, default `[IP Sentry] IP {ip} has been banned` |
| `Body` | `*func(ip, reason string) string` | Custom body, default `[IP Sentry] IP {ip} has been banned for {reason}` |

### Runtime Files

| File | Description |
|------|-------------|
| `.sessionSecret` | Session signing key in the working directory (mode `0600`), generated when missing; deleting it invalidates every existing session |
| `./whiteList.json` | Allow list, overwritten on `Allow.Add()` |
| `./blackList.json` | Deny list, overwritten on `Deny.Add()` |

List file format:

```json
[
  {
    "ip": "203.0.113.10",
    "reason": "office gateway",
    "added_at": 1735689600
  }
]
```

## Usage

### Basic: net/http

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

	// Every request passes through Check; failures return JSON {"error": "..."}
	log.Fatal(http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", sentry.HTTPMiddleware(mux)))
}
```

### Gin with GeoLite2

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

### Report Login Failures and 404s

`LoginFailure()` and `NotFound404()` accumulate counts per session (1-hour expiry) that feed into the next score.

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

### Manage Lists Manually

```go
// Allow list: later requests skip every check
if err := sentry.Manager.Allow.Add("203.0.113.10", "office gateway"); err != nil {
	log.Printf("allow: %v", err)
}

// Deny list: permanent rejection, sends an email asynchronously when configured
if err := sentry.Manager.Deny.Add("198.51.100.7", "credential stuffing"); err != nil {
	log.Printf("deny: %v", err)
}

// Temporary block: repeated calls grow by 2^count, capped at BlockTimeMax
if err := sentry.Manager.Block.Add("192.0.2.33", "manual review"); err != nil {
	log.Printf("block: %v", err)
}

allowed := sentry.Manager.Allow.Check("203.0.113.10")
denied := sentry.Manager.Deny.Check("198.51.100.7")
blocked := sentry.Manager.Block.IsBlock("192.0.2.33")
log.Println(allowed, denied, blocked)
```

### Call Check Without Middleware

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

## API Reference

### Lifecycle

| Function | Signature | Description |
|----------|-----------|-------------|
| `New` | `func New(c Config) (*IPGuardian, error)` | Applies Log/Redis defaults, connects and pings Redis, loads Allow/Deny list files, opens GeoLite2 |
| `Close` | `func (i *IPGuardian) Close() error` | Closes Redis, GeoLite2, and the Logger |

### Check and Middleware

| Function | Signature | Description |
|----------|-----------|-------------|
| `Check` | `func (i *IPGuardian) Check(r *http.Request, w http.ResponseWriter) IPGuardianResult` | Allow passes → Block/Deny rejects → four-dimension scoring → tiered rate limit; writes session and fingerprint cookies |
| `HTTPMiddleware` | `func (i *IPGuardian) HTTPMiddleware(next http.Handler) http.Handler` | `net/http` middleware, responds with JSON `{"error": "..."}` on failure |
| `GinMiddleware` | `func (i *IPGuardian) GinMiddleware() gin.HandlerFunc` | Gin middleware, calls `c.Abort()` on failure |
| `LoginFailure` | `func (i *IPGuardian) LoginFailure(w http.ResponseWriter, r *http.Request) error` | Increments the current session's login failure count |
| `NotFound404` | `func (i *IPGuardian) NotFound404(w http.ResponseWriter, r *http.Request) error` | Increments the current session's 404 count |

### IPGuardianResult

```go
type IPGuardianResult struct {
	Success    bool   `json:"success"`
	StatusCode int    `json:"status_code"`
	Error      string `json:"error"`
}
```

| StatusCode | Case |
|------------|------|
| `200` | Passed |
| `403` | Blocked/denied, score ≥ 100, or over the tier's rate limit |
| `500` | Client IP cannot be resolved or session creation failed |

### List Management (`IPGuardian.Manager`)

| Method | Signature | Description |
|--------|-----------|-------------|
| `Allow.Add` | `func (m *AllowIPManager) Add(ip string, tag string) error` | Writes to memory, Redis (no expiry), and the list file |
| `Allow.Check` | `func (m *AllowIPManager) Check(ip string) bool` | Checks Redis first, falls back to the memory cache |
| `Deny.Add` | `func (m *DenyIPManager) Add(ip, reason string) error` | Writes to memory, Redis (no expiry), and the list file, then sends email asynchronously |
| `Deny.Check` | `func (m *DenyIPManager) Check(ip string) bool` | Checks Redis first, falls back to the memory cache |
| `Block.Add` | `func (m *BlockIPManager) Add(ip string, reason string) error` | Temporary block; if already blocked, increments the count, appends the reason, and extends the duration |
| `Block.IsBlock` | `func (m *BlockIPManager) IsBlock(ip string) bool` | Whether the IP is currently blocked |

### Client IP Resolution Order

Takes the first valid IP from these headers in order, falling back to `RemoteAddr`:

`CF-Connecting-IP` → `X-Forwarded-For` → `X-Real-IP` → `X-Client-IP` → `X-Cluster-Client-IP` → `X-Forwarded` → `Forwarded-For` → `Forwarded`

Clients can forge these headers; have the front proxy overwrite or strip them in production.

### Redis Keys

| Key | TTL | Purpose |
|-----|-----|---------|
| `allow:{ip}` / `deny:{ip}` | None | Lists |
| `block:{ip}` | Block duration | Temporary block |
| `frequency:{ip}:{minute}` | 2 minutes | Per-minute request count |
| `session:ip:{sid}` / `ip:device:{ip}` / `device:fp:{fp}` | 1 hour | Correlation sets |
| `fp:session:{minute}:{fp}` | 1 minute | Sessions per fingerprint |
| `geo:ip:{ip}` | 24 hours | GeoLite2 lookup cache |
| `geo:locations:{sid}` | 24 hours | Last 10 locations |
| `interval:{sid}` / `interval:last:{sid}` | 1 hour | Request intervals |
| `session:start:{sid}` | 15 minutes (sliding) | Session start time |
| `login:failure:{sid}` / `notfound:404:{sid}` | 1 hour | Reported counts |

***

©️ 2025 [邱敬幃 Pardn Chiu](https://www.linkedin.com/in/pardnchiu)
