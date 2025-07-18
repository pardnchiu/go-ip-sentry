> [!Note]
> This content is translated by LLM. Original text can be found [here](README.zh.md)

# IP Sentry

> A Go-based IP security protection package providing real-time threat detection, dynamic risk scoring, device fingerprinting, and multi-layered security mechanisms.

![lang](https://img.shields.io/badge/lang-go-blue)
[![license](https://img.shields.io/github/license/pardnchiu/go-ip-sentry)](LICENSE)
[![version](https://img.shields.io/github/v/tag/pardnchiu/go-ip-sentry)](https://github.com/pardnchiu/go-ip-sentry/releases)
![card](https://goreportcard.com/badge/github.com/pardnchiu/go-ip-sentry)<br>
[![readme](https://img.shields.io/badge/readme-EN-white)](README.md)
[![readme](https://img.shields.io/badge/readme-ZH-white)](README.zh.md) 

## Three Core Features

### Multi-Layer Security Protection
- **Whitelist Management**: Trusted list automatically bypasses security checks with file synchronization support
- **Blacklist System**: Permanent blocking of malicious IPs with integrated email notification
- **Dynamic Blocking**: Temporary blocking of suspicious activities using exponential time growth
- **Auto Escalation**: Repeated blocks automatically upgrade to permanent bans

### Intelligent Threat Detection
- **Device Fingerprinting**: SHA256 encrypted unique device identification with 365-day tracking
- **Behavioral Analysis**: Request patterns, time intervals, and session tracking
- **Geographic Monitoring**: Cross-country hopping, rapid location changes, and high-risk region detection
- **Correlation Analysis**: Multi-device, multi-IP, and multi-session anomaly detection
- **Login Behavior**: Login failure counts and 404 error frequency monitoring

### Dynamic Scoring System (Customizable Thresholds)
- **Real-time Calculation**: Multi-dimensional risk factor parallel computation
- **Adaptive Adjustment**: Dynamic rate limiting based on threat levels
- **Threshold Management**: Three-tier classification: suspicious, dangerous, blocking
- **Auto Rate Limiting**: Normal, suspicious, dangerous three-level restrictions

## Flow Charts

<details>
<summary>Main Flow</summary>

```mermaid
graph TD
  A[HTTP Request Entry] --> B[Start Check Process]
  B --> C[Get Device Info]
  C --> C1[See Device Info Flow]:::module
  C1 --> D[Device Info Created]
  D --> D1{Device Info Success?}
  D1 -->|Failed| REJECT
  D1 -->|Success| E[Start Main Validation]
  E --> |Whitelist| SUCCESS[Allow Access]
  E -->|Blacklist| REJECT[Reject Request]
  E -->|Blocklist| I{Exceeded Block-to-Ban Count}
  I -->|Yes| J[Add to Blacklist and Notify Developer]
  J --> REJECT
  I -->|No| REJECT
  E -->|No Flag| FFF{Has AbuseIPDB Token}
  FFF -->|Yes| ABUSE[Call AbuseIPDB for Risk Score]
  ABUSE --> ABUSE1[See AbuseIPDB Check Flow]:::module
  ABUSE1 --> ABUSE2{Is Malicious IP?}
  ABUSE2 -->|Yes| AD12[Add to Blocklist]
  ABUSE2 -->|No| L[Call Dynamic Scoring for Risk Assessment]
  FFF -->|No| L
  L --> L1[See Dynamic Scoring Flow]:::module
  L1 --> R1{Dynamic Scoring Success?}
  R1 -->|Failed| REJECT
  R1 -->|Success| T{Reached Block Score}
  T -->|Yes| AD12
  AD12 --> REJECT
  T -->|No| V{Check Risk-Based Rate Limit}
  V -->|No| SUCCESS:::success
  V -->|Yes| REJECT:::danger
  
  classDef module fill:#3498db,stroke:#2980b9,color:#ffffff
  classDef success fill:#2ecc71,stroke:#27ae60,color:#ffffff
  classDef danger fill:#e74c3c,stroke:#c0392b,color:#ffffff
```

</details>

<details>
<summary>Device Information</summary>

```mermaid
graph TD
  A[Receive HTTP Request] --> B[getDevice Extract Device Info]
  
  B --> C[r.UserAgent Get User-Agent]
  C --> D[getClientIP IP Address Resolution]
  
  D --> E[Check Proxy Server Header Priority]
  E --> F1[CF-Connecting-IP Cloudflare]
  E --> F2[X-Forwarded-For Standard Reverse Proxy]
  E --> F3[X-Real-IP Nginx]
  E --> F4[X-Client-IP Apache]
  E --> F5[Other Proxy Headers]
  
  F1 --> G[Parse and Validate IP Format]
  F2 --> G
  F3 --> G
  F4 --> G
  F5 --> G
  
  G --> H{Valid Proxy IP?}
  H -->|No| I[Use RemoteAddr]
  H -->|Yes| J[isInternalIP Internal Network Check]
  I --> J
  
  J --> K[hasProxyHeader Proxy Header Check]
  K --> L{Has Proxy Header?}
  L -->|Yes| M[checkProxy Proxy Chain Validation]
  L -->|No| N[Direct IP Internal Network Check]
  
  M --> O[isInternalIPRange CIDR Check]
  N --> O
  O --> P[Set isPrivate and ipTrustLevel]
  
  P --> Q[User-Agent Parsing Flow]
  Q --> R[getPlatform Platform Identification]
  R --> S[getBrowser Browser Identification]
  S --> T[getType Device Type Identification]
  T --> U[getOS Operating System Identification]
  
  U --> V[Create Basic Device Structure]
  V --> W[Manager Status Check]
  W --> X[Trust.check Trust List Check]
  X --> Y[Ban.check Block List Check]
  Y --> Z[Block.check Block List Check]
  
  Z --> AA[requestCountInMin Minute Request Count]
  AA --> BB[blockCountInHour Hour Block Count]
  
  BB --> CC[getSessionID Session Management]
  CC --> DD{Session Cookie Exists?}
  
  DD -->|Yes| EE[parseSignedSessionID Parse Signature]
  EE --> FF{HMAC-SHA256 Signature Valid?}
  FF -->|Yes| GG[Extend Cookie 30 Days]
  FF -->|No| HH[createSignedSessionID Create New Session]
  
  DD -->|No| HH
  HH --> II[generateSessionID Generate 32-char ID]
  II --> JJ[signSessionID HMAC Signature]
  JJ --> KK[Format: s:sessionID.signature]
  KK --> LL[Set 30-day HttpOnly Cookie]
  
  GG --> MM[getFingerprint Device Fingerprint Generation]
  LL --> MM
  
  MM --> NN{Device Cookie Exists?}
  NN -->|Yes| OO[Read Existing Device Key]
  NN -->|No| PP[uuid Generate 128-char Random Key]
  
  OO --> QQ[Extend Cookie 365 Days]
  PP --> RR[Set 365-day HttpOnly Cookie]
  
  QQ --> SS[Create Fingerprint Info String]
  RR --> SS
  SS --> TT[Platform/Browser/Type/System/Key]
  TT --> UU[SHA256 Hash Calculation]
  UU --> VV[hex.EncodeToString Fingerprint Generation]
  
  VV --> WW[Return Complete Device Structure]
  
  subgraph "IP Address Resolution & Proxy Detection"
  D
  E
  F1
  F2
  F3
  F4
  F5
  G
  H
  I
  J
  K
  L
  M
  N
  O
  P
  end
  
  subgraph "User-Agent Parsing Engine"
  Q
  R
  S
  T
  U
  end
  
  subgraph "Security Status Check"
  W
  X
  Y
  Z
  AA
  BB
  end
  
  subgraph "Session Management (30-day Sliding Window)"
  CC
  DD
  EE
  FF
  GG
  HH
  II
  JJ
  KK
  LL
  end
  
  subgraph "Device Fingerprint Tracking (365-day Sliding Window)"
  MM
  NN
  OO
  PP
  QQ
  RR
  SS
  TT
  UU
  VV
  end
  
  classDef success fill:#2ecc71,stroke:#27ae60,color:#ffffff
  
  class WW success
  class X,Y,Z security
  class R,S,T,U process
  class II,JJ,UU,VV crypto
```

</details>

<details>
<summary>Dynamic Scoring</summary>

```mermaid
graph TD
  A[Start Dynamic Score Calculation dynamicScore] --> B[Initialize Parallel Execution Environment]
  B --> C[Create WaitGroup, Mutex, errChan]
  C --> D[Initialize Shared Results: combinedFlags, combinedScore]
  
  D --> E[Launch Four Goroutines Simultaneously]
  
  E --> |wg.Add| I1[Define Basic Item Operation Matrix]
  E --> |wg.Add| I2{Geo Checker & Database Available?}
  E --> |wg.Add| I3[Redis Pipeline Get Interval Data]
  E --> |wg.Add| I4[Calculate Current Minute Timestamp]
  
  I1 --> J1[Redis Pipeline Batch Operations]
  J1 --> K1[SAdd + SCard + Expire Correlation Analysis]
  K1 --> L1[Threshold Decision: Count > Threshold * 1.5]
  L1 --> M1[Generate localFlags, localScore]
  M1 --> N1[mu.Lock Safe Result Merge]
  
  I2 -->|No| J2[return nil Skip Detection]
  I2 -->|Yes| K2[net.ParseIP Address Resolution]
  K2 --> L2[GeoIP2 Country Query]
  L2 --> M2[Redis LPUSH Location History]
  M2 --> N2[Analyze 1-hour Location Changes]
  N2 --> O2[Detect Geographic Hopping/Switching/Rapid Changes]
  O2 --> P2[mu.Lock Safe Result Merge]
  J2 --> P2
  
  I3 --> J3[Calculate Request Time Intervals]
  J3 --> K3[Statistical Analysis: Mean, Variance]
  K3 --> L3[Detect Regularity, Frequent Requests, Extreme Patterns]
  L3 --> M3[Session Duration Layered Detection]
  M3 --> N3[mu.Lock Safe Result Merge]
  
  I4 --> J4[Redis SADD Fingerprint-Session Association]
  J4 --> K4[Redis SCARD Calculate Session Count]
  K4 --> L4{Session Count > 2?}
  L4 -->|Yes| M4[Flag fp_multi_session]
  L4 -->|No| N4[No Anomaly Flag]
  M4 --> O4[mu.Lock Safe Result Merge]
  N4 --> O4
  
  N1 --> Q[wg.Done Completion Notification]
  P2 --> Q
  N3 --> Q
  O4 --> Q
  
  Q --> R[wg.Wait All Goroutines Complete]
  R --> S[close errChan Error Channel]
  S --> T[range errChan Check Errors]
  T --> U{Any Errors?}
  U -->|Yes| KK
  U -->|No| W[calcScore Calculate Final Risk]
  
  W --> X[Comprehensive Risk Detection: Detail > 4]
  X --> Y[math.Min Score Cap 100]
  Y --> Z{Total Risk > 100?}
  Z -->|Yes| AA[Manager.Block.Add Auto Block]
  Z -->|No| BB[Risk Level Classification]
  
  AA --> CC[IsBlock: true]
  
  BB --> DD[Create ScoreItem Structure]
  DD --> EE[IsBlock: Total Risk >= 100]
  EE --> FF[IsSuspicious: Total Risk >= ScoreSuspicious]
  FF --> GG[IsDangerous: Total Risk >= ScoreDangerous]
  GG --> HH[Flag: combinedFlags]
  HH --> II[Score: Total Risk]
  II --> JJ[Detail: combinedScore.Detail]
  
  JJ --> KK[Return Complete ScoreItem]:::success
  CC --> KK
  
  subgraph "Parallel Goroutine Execution Group"
  subgraph "calcBasic: Basic Correlation Detection"
    I1
    J1
    K1
    L1
    M1
    N1
  end
  
  subgraph "calcGeo: Geographic Location Analysis"
    I2
    J2
    K2
    L2
    M2
    N2
    O2
    P2
  end
  
  subgraph "calcBehavior: Time Pattern Analysis"
    I3
    J3
    K3
    L3
    M3
    N3
  end
  
  subgraph "calcFingerprint: Fingerprint Correlation"
    I4
    J4
    K4
    L4
    M4
    N4
    O4
  end
  end
  
  subgraph "Synchronization Control & Error Handling"
  Q
  R
  S
  T
  U
  end
  
  subgraph "Final Risk Assessment & Result Construction"
  W
  X
  Y
  Z
  AA
  BB
  CC
  DD
  EE
  FF
  GG
  HH
  II
  JJ
  KK
  end
  
  classDef success fill:#2ecc71,stroke:#27ae60,color:#ffffff
  
  class I1,I2,I3,I4 parallel
  class Q,R,S,T sync
  class J1,J3,J4,K1,K2,K3,K4 calc
```

</details>

<details>
<summary>AbuseIPDB (Not Yet Implemented)</summary>

```mermaid
flowchart TD
  START["External IP Address"] --> TOKEN{"AbuseIPDB Token Check"}
  
  TOKEN -->|"Token Not Found"| NO_TOKEN["Skip Threat Intelligence Check"]
  TOKEN -->|"Token Found"| CACHE{"AbuseIPDB Cache Check"}
  
  CACHE -->|"Cache Hit"| REPUTATION{"IP Reputation Verification"}
  CACHE -->|"Cache Miss"| API_QUERY["AbuseIPDB API Query & Update Cache (24 hours)"]
  
  API_QUERY --> API_STATUS{"API Response Status"}
  API_STATUS -->|"Query Failed"| API_FAIL["API Query Failed"]
  API_STATUS -->|"Query Success"| REPUTATION
  
  REPUTATION -->|"Confirmed Malicious IP"| MALICIOUS["Flag as Threat IP"]
  REPUTATION -->|"Normal Reputation"| CLEAN["Flag as Clean IP"]
  
  NO_TOKEN --> SKIP["Skip Check Result"]
  API_FAIL --> SKIP
  MALICIOUS --> RESULT["Return Check Result"]
  CLEAN --> RESULT
  SKIP --> RESULT
```

</details>

## Dependencies

- [`github.com/gin-gonic/gin`](https://github.com/gin-gonic/gin)
- [`github.com/redis/go-redis/v9`](https://github.com/redis/go-redis)
- [`github.com/oschwald/geoip2-golang`](https://github.com/oschwald/geoip2-golang)
- [`github.com/pardnchiu/go-logger`](https://github.com/pardnchiu/go-logger): If you don't need this dependency, you can fork the project and replace it with your preferred logging solution. You can also vote [here](https://forms.gle/EvNLwzpHfxWR2gmP6) to let me know your preference.

## Usage

### Installation
```bash
go get github.com/pardnchiu/go-ip-sentry
```

### Basic Initialization
```go
package main

import (
  "log"
  "net/http"
  
  is "github.com/pardnchiu/go-ip-sentry"
)

func main() {
  config := is.Config{
    Redis: is.Redis{
      Host:     "localhost",
      Port:     6379,
      Password: "",
      DB:       0,
    },
    Log: &is.Log{
      Path:    "./logs/ip-sentry",
      Stdout:  false,
      MaxSize: 16 * 1024 * 1024,
    },
    Filepath: is.Filepath{
      CityDB:    "./GeoLite2-City.mmdb",
      CountryDB: "./GeoLite2-Country.mmdb",
      WhiteList: "./whiteList.json",
      BlackList: "./blackList.json",
    },
    Parameter: is.Parameter{
      BlockToBan:             3,
      BlockTimeMin:           30 * time.Minute,
      BlockTimeMax:           1800 * time.Minute,
      RateLimitNormal:        100,
      RateLimitSuspicious:    50,
      RateLimitDangerous:     20,
      ScoreSuspicious:        50,
      ScoreDangerous:         80,
    },
  }
  
  guardian, err := is.New(config)
  if err != nil {
    log.Fatal(err)
  }
  defer guardian.Close()
  
  // HTTP middleware
  handler := guardian.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Welcome"))
  }))
  
  http.Handle("/", handler)
  log.Println("Server starting on :8080")
  log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### Gin Framework Integration
```go
package main

import (
  "github.com/gin-gonic/gin"
  is "github.com/pardnchiu/go-ip-sentry"
)

func main() {
  config := is.Config{
    // Same configuration as above
  }
  
  guardian, err := is.New(config)
  if err != nil {
    panic(err)
  }
  defer guardian.Close()
  
  r := gin.Default()
  
  // Use IP Sentry middleware
  r.Use(guardian.GinMiddleware())
  
  r.GET("/", func(c *gin.Context) {
    c.JSON(200, gin.H{
      "message": "Welcome",
    })
  })
  
  r.Run(":8080")
}
```

## Configuration Reference

```go
type Config struct {
  Redis     Redis        `json:"redis"`     // Redis connection config
  Email     *EmailConfig `json:"email"`     // Email notification config
  Log       *Log         `json:"log"`       // Logging config
  Filepath  Filepath     `json:"filepath"`  // File path config
  Parameter Parameter    `json:"parameter"` // Parameter config
}

type Redis struct {
  Host     string `json:"host"`     // Redis host
  Port     int    `json:"port"`     // Redis port
  Password string `json:"password"` // Redis password
  DB       int    `json:"db"`       // Redis database
}

type EmailConfig struct {
  Host     string                                 `json:"host"`     // SMTP host
  Port     int                                    `json:"port"`     // SMTP port
  Username string                                 `json:"username"` // SMTP username
  Password string                                 `json:"password"` // SMTP password
  From     string                                 `json:"from"`     // Sender
  To       []string                               `json:"to"`       // Recipients
  CC       []string                               `json:"cc"`       // CC recipients
  Subject  *func(ip string, reason string) string `json:"-"`        // Custom subject
  Body     *func(ip string, reason string) string `json:"-"`        // Custom body
}

type Log struct {
  Path      string // Log directory path (default: ./logs/mysqlPool)
  Stdout    bool   // Enable console output (default: false)
  MaxSize   int64  // Max size before file rotation (default: 16*1024*1024)
  MaxBackup int    // Number of log files to keep (default: 5)
  Type      string // Output format: "json" for slog standard, "text" for tree format (default: "text")
}

type Filepath struct {
  CityDB    string `json:"city_db"`    // GeoLite2-City.mmdb
  CountryDB string `json:"country_db"` // GeoLite2-Country.mmdb
  WhiteList string `json:"trust_list"` // Whitelist file
  BlackList string `json:"ban_list"`   // Blacklist file
}

type Parameter struct {
  HighRiskCountry        []string       `json:"high_risk_country"`         // High-risk country list
  BlockToBan             int            `json:"block_to_ban"`              // Block-to-ban count threshold
  BlockTimeMin           time.Duration  `json:"block_time_min"`            // Minimum block time
  BlockTimeMax           time.Duration  `json:"block_time_max"`            // Maximum block time
  RateLimitNormal        int            `json:"rate_limit_normal"`         // Normal request rate limit
  RateLimitSuspicious    int            `json:"rate_limit_suspicious"`     // Suspicious request rate limit
  RateLimitDangerous     int            `json:"rate_limit_dangerous"`      // Dangerous request rate limit
  SessionMultiIP         int            `json:"session_multi_ip"`          // Max IPs per session
  IPMultiDevice          int            `json:"ip_multi_device"`           // Max devices per IP
  DeviceMultiIP          int            `json:"device_multi_ip"`           // Max IPs per device
  LoginFailure           int            `json:"login_failure"`             // Max login failures per session
  NotFound404            int            `json:"not_found_404"`             // Max 404 requests per session
  ScoreSuspicious        int            `json:"score_suspicious"`          // Suspicious request threshold
  ScoreDangerous         int            `json:"score_dangerous"`           // Dangerous request threshold
  ScoreSessionMultiIP    int            `json:"score_session_multi_ip"`    // Multi-IP session risk score
  ScoreIPMultiDevice     int            `json:"score_ip_multi_device"`     // Multi-device IP risk score
  ScoreDeviceMultiIP     int            `json:"score_device_multi_ip"`     // Multi-IP device risk score
  ScoreFpMultiSession    int            `json:"score_fp_multi_session"`    // Multi-session fingerprint score
  ScoreGeoHighRisk       int            `json:"score_geo_high_risk"`       // High-risk geographic score
  ScoreGeoHopping        int            `json:"score_geo_hopping"`         // Geographic hopping score
  ScoreGeoFrequentSwitch int            `json:"score_geo_frequent_switch"` // Frequent geo switch score
  ScoreGeoRapidChange    int            `json:"score_geo_rapid_change"`    // Rapid geo change score
  ScoreIntervalRequest   int            `json:"score_interval_request"`    // Short interval request score
  ScoreFrequencyRequest  int            `json:"score_frequency_request"`   // Request frequency score
  ScoreLongConnection    int            `json:"score_long_connection"`     // Long connection score
  ScoreLoginFailure      int            `json:"score_login_failure"`       // Login failure score
  ScoreNotFound404       int            `json:"score_not_found_404"`       // 404 request score
}
```

## Available Functions

### Instance Management

- **New** - Create new instance
  ```go
  guardian, err := is.New(config)
  ```

- **Close** - Close instance
  ```go
  err := guardian.Close()
  ```

### IP Management

- **Check** - IP check
  ```go
  result := guardian.Check(r, w)
  ```

- **Allow.Add** - Add to whitelist
  ```go
  err := guardian.Manager.Allow.Add("192.168.1.100", "Internal server")
  ```

- **Deny.Add** - Add to blacklist
  ```go
  err := guardian.Manager.Deny.Add("1.2.3.4", "Malicious attack")
  ```

- **Block.Add** - Add to blocklist
  ```go
  err := guardian.Manager.Block.Add("5.6.7.8", "Suspicious behavior")
  ```

- **LoginFailure** - Login failure
  ```go
  err := guardian.LoginFailure(w, r)
  ```

- **NotFound404** - 404 error
  ```go
  err := guardian.NotFound404(w, r)
  ```

#### Middleware Usage
```go
// Standard HTTP middleware
handler := guardian.HTTPMiddleware(yourHandler)

// Gin middleware
router.Use(guardian.GinMiddleware())
```

## List Formats

### whiteList.json
```json
[
  {
    "ip": "192.168.1.100",
    "reason": "Internal server",
    "added_at": 1703980800
  }
]
```

### blackList.json
```json
[
  {
    "ip": "1.2.3.4",
    "reason": "Malicious attack",
    "added_at": 1703980800
  }
]
```

### Risk Scoring System

#### Basic Checks
- **Session Multi-IP Check**: Single session using multiple IPs
- **IP Multi-Device Check**: Single IP corresponding to multiple device fingerprints
- **Device Multi-IP Check**: Single device using multiple IPs
- **Login Failure Monitoring**: Record failure count, trigger risk when exceeding threshold
- **404 Error Tracking**: Monitor abnormal path probing behavior

#### Geographic Analysis
- **High-Risk Countries**: Configurable high-risk region list
- **Geographic Hopping**: Alert triggered by >4 countries within 1 hour
- **Frequent Switching**: City switching >4 times within 1 hour
- **Rapid Changes**: Movement speed >800 km/h or crossing 500 km within 30 minutes
- **Distance Calculation**: Uses Haversine formula for Earth surface distance

#### Behavioral Analysis
- **Request Interval Regularity Detection**: Variance <1000 with regular intervals
- **Long Connection Time Monitoring**: Tiered alerts for >1/2/4 hours
- **Frequent Request Pattern Identification**: >16 requests within 500ms
- **Extreme Regularity Detection**: Variance <100 with ≥8 samples

#### Fingerprint Analysis
- **Same Fingerprint Multi-Session Detection**: Single fingerprint >2 sessions within 1 minute
- **Minute-Level Statistical Protection**: Uses timestamp segmentation to avoid false positives

## License

This source code project is licensed under the [MIT](LICENSE) license.

## Author

<img src="https://avatars.githubusercontent.com/u/25631760" align="left" width="96" height="96" style="margin-right: 0.5rem;">

<h4 style="padding-top: 0">邱敬幃 Pardn Chiu</h4>

<a href="mailto:dev@pardn.io" target="_blank">
  <img src="https://pardn.io/image/email.svg" width="48" height="48">
</a> <a href="https://linkedin.com/in/pardnchiu" target="_blank">
  <img src="https://pardn.io/image/linkedin.svg" width="48" height="48">
</a>

***

©️ 2025 [邱敬幃 Pardn Chiu](https://pardn.io)
