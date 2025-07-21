# go-ip-sentry - 架構

最後更新：2026-10-05

> 返回 [README](./README.zh.md)

## 概覽

```mermaid
graph TB
    REQ[HTTP 請求] --> MW[中介層<br/>GinMiddleware / HTTPMiddleware]
    MW --> CHK[IPGuardian.Check]
    CHK --> DEV[裝置識別<br/>getDevice]
    DEV --> MGR[名單管理<br/>Allow / Deny / Block]
    CHK --> SCORE[動態評分<br/>dynamicScore]
    SCORE --> BASIC[關聯]
    SCORE --> GEOS[地理]
    SCORE --> BEH[行為]
    SCORE --> FP[指紋]
    GEOS --> GEO[GeoLite2]
    BASIC & GEOS & BEH & FP & MGR & DEV <--> REDIS[(Redis)]
    MGR --> FILE[(名單 JSON 檔)]
    MGR --> SMTP[SMTP 通知]
    CHK --> RES[IPGuardianResult]
```

## 模組：Instance

建立實例、套用預設值並串接檢查流程。

```mermaid
graph TB
    subgraph Instance
        NEW[New] --> LOG[validLoggerConfig<br/>go-logger]
        NEW --> RC[redis.NewClient + PING]
        NEW --> MAN[Manager<br/>Allow / Deny / Block]
        NEW --> G2[newGeoLite2]
        CHK[Check] --> DEFAULTS[速率限制預設值]
        CHK --> DS[dynamicScore]
        CLOSE[Close] --> RC
        CLOSE --> G2
        CLOSE --> LOG
    end
    CFG[Config] --> NEW
    MW[中介層] --> CHK
```

```mermaid
classDiagram
    class IPGuardian {
        +Context context.Context
        +Config *Config
        +Redis *redis.Client
        +Logger *Logger
        +GeoLite2 *GeoLite2
        +Manager *Manager
        +Check(r, w) IPGuardianResult
        +GinMiddleware() gin.HandlerFunc
        +HTTPMiddleware(next) http.Handler
        +LoginFailure(w, r) error
        +NotFound404(w, r) error
        +Close() error
    }
    class Manager {
        +Allow *AllowIPManager
        +Block *BlockIPManager
        +Deny *DenyIPManager
    }
    class Config {
        +Redis Redis
        +Email *EmailConfig
        +Log *Log
        +Filepath Filepath
        +Parameter Parameter
    }
    class IPGuardianResult {
        +Success bool
        +StatusCode int
        +Error string
    }
    IPGuardian --> Manager
    IPGuardian --> Config
    IPGuardian ..> IPGuardianResult
```

## 模組：Device

由請求解析用戶端 IP、User-Agent、Session 與裝置指紋，並附帶名單狀態與計數。

```mermaid
graph TB
    subgraph Device
        GD[getDevice] --> IP[getClientIP<br/>代理標頭 → RemoteAddr]
        IP --> INT[isInternalIP<br/>內網 CIDR 判斷]
        GD --> UA[UA 解析<br/>Platform / Browser / Type / OS]
        GD --> FLAGS[名單狀態<br/>Trust / Ban / Block]
        GD --> RCNT[requestCountInMin]
        GD --> BCNT[blockCountInHour]
        GD --> SID[getSessionID]
        SID --> SIGN[HMAC-SHA256 簽章<br/>s:id.sig]
        SIGN --> SEC[.sessionSecret]
        GD --> FPR[getFingerprint<br/>SHA-256 UA + 裝置 Cookie]
    end
    REQ[http.Request] --> GD
    SID --> CK1[Cookie conn.sess.id]
    FPR --> CK2[Cookie conn.device.id]
    RCNT --> REDIS[(Redis)]
    BCNT --> REDIS
    FLAGS --> MGR[Manager]
```

## 模組：Score

四個維度以 goroutine 並行計算，各自累積分數後以 mutex 合併。

```mermaid
graph TB
    subgraph Score
        DS[dynamicScore] --> CB[calcBasic]
        DS --> CG[calcGeo]
        DS --> CBH[calcBehavior]
        DS --> CF[calcFingerprint]
        CB --> MERGE[合併 Flag / Detail]
        CG --> MERGE
        CBH --> MERGE
        CF --> MERGE
        MERGE --> CS[calcScore<br/>Detail > 4 加 25，上限 100]
        CS --> ITEM[ScoreItem<br/>IsBlock / IsSuspicious / IsDangerous]
    end
    CB --> R1[Session↔IP / IP↔裝置 / 裝置↔IP<br/>登入失敗 / 404]
    CBH --> R2[請求間隔變異數<br/>Session 持續時間]
    CF --> R3[同分鐘指紋 Session 數]
    CG --> GEO[GeoLite2.risk]
    R1 & R2 & R3 --> REDIS[(Redis)]
```

## 模組：GeoLite2

查詢 IP 位置並快取，依最近 10 筆位置歷史判定地理風險。

```mermaid
graph TB
    subgraph GeoLite2
        LOC[location] --> INTL{內網 IP?}
        INTL -->|是| EMPTY[空位置]
        INTL -->|否| GET[get<br/>Redis 快取]
        GET -->|未命中| Q[query]
        Q --> CITY[CityDB.City]
        Q -->|City 失敗| COUNTRY[CountryDB.Country]
        Q --> SET[set<br/>快取 24 小時]
        RISK[risk] --> HR[checkHighRisk]
        RISK --> HOP[checkHopping<br/>1 小時 > 4 國]
        RISK --> SW[checkFrequentSwitch<br/>城市切換 > 4 次]
        RISK --> RAPID[checkRapidChange<br/>Haversine 時速 > 800]
    end
    CG[calcGeo] --> LOC
    CG --> HIST[geo:locations 最近 10 筆]
    HIST --> RISK
    MMDB[(GeoLite2 mmdb)] --> CITY
    MMDB --> COUNTRY
```

## 模組：Manager

三層名單：Allow／Deny 為永久名單並持久化至檔案，Block 為帶 TTL 的暫時封鎖。

```mermaid
graph TB
    subgraph Manager
        subgraph Allow
            AL[load] --> AC[(記憶體 Cache)]
            AA[Add] --> AC
            AA --> AS[save]
            ACK[Check]
        end
        subgraph Deny
            DL[load] --> DC[(記憶體 Cache)]
            DA[Add] --> DC
            DA --> DSV[save]
            DA --> MAIL[sendEmail<br/>goroutine]
            DCK[Check]
        end
        subgraph Block
            BA[Add] --> CHKB[checkBlockIP]
            CHKB --> TTL[時長 = 2^count × BlockTimeMin<br/>上限 BlockTimeMax]
            BIS[IsBlock]
        end
    end
    AF[(whiteList.json)] --> AL
    AS --> AF
    DF[(blackList.json)] --> DL
    DSV --> DF
    AA & ACK & DA & DCK & TTL & BIS <--> REDIS[(Redis)]
    MAIL --> SMTP[SMTP]
```

## 資料流

```mermaid
sequenceDiagram
    participant C as 用戶端
    participant MW as 中介層
    participant G as IPGuardian
    participant D as Device
    participant M as Manager
    participant S as Score
    participant R as Redis
    participant H as 下游 Handler

    C->>MW: HTTP 請求
    MW->>G: Check(r, w)
    G->>D: getDevice
    D->>M: Allow / Deny / Block 狀態
    M->>R: EXISTS allow / deny / block
    D->>R: INCR frequency:{ip}:{minute}
    D-->>C: Set-Cookie Session / 裝置
    D-->>G: Device
    alt Trust
        G-->>MW: 200
    else Block / Ban
        G-->>MW: 403
    else 未列入
        par 四維並行
            G->>S: calcBasic
            G->>S: calcGeo
            G->>S: calcBehavior
            G->>S: calcFingerprint
        end
        S->>R: Pipeline 讀寫
        S-->>G: ScoreItem
        alt 分數 ≥ 100 或超過分級速率
            G-->>MW: 403
        else
            G-->>MW: 200
        end
    end
    alt Success
        MW->>H: next
        H-->>C: 回應
    else 失敗
        MW-->>C: JSON error
    end
```

## 狀態機

單一 IP 在 Check 流程中的狀態。

```mermaid
stateDiagram-v2
    [*] --> 未列入
    未列入 --> 信任: Allow.Add
    未列入 --> 封鎖: Block.Add
    未列入 --> 拒絕: Deny.Add
    封鎖 --> 封鎖: Block.Add（次數 +1、時長倍增）
    封鎖 --> 未列入: TTL 到期
    封鎖 --> 拒絕: Deny.Add
    未列入 --> 正常: 分數 < ScoreSuspicious
    未列入 --> 可疑: 分數 ≥ ScoreSuspicious
    未列入 --> 危險: 分數 ≥ ScoreDangerous
    正常 --> 未列入: 下一次請求重新評分
    可疑 --> 未列入: 下一次請求重新評分
    危險 --> 未列入: 下一次請求重新評分
    信任 --> [*]
    拒絕 --> [*]
```

***

©️ 2025 [邱敬幃 Pardn Chiu](https://www.linkedin.com/in/pardnchiu)
